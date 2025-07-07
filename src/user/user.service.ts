import {
    BadRequestException,
    Injectable,
    NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { UserResponseDTO } from './dtos/userResponse.dto';
import { User } from '@prisma/client';
import { UserRole as AppUserRole } from '../enums/userRole';
import { UpdateUserDto } from './dtos/updateUser.dto';
import { AuthService } from 'src/auth/auth.service';

@Injectable()
export class UserService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly auth: AuthService,
    ) {}

    /**
     * Converts a Prisma User model into a UserResponseDTO including categories.
     * @private
     * @param {User} user - The user object from the database.
     * @returns {Promise<UserResponseDTO>} A user DTO formatted for responses.
     */
    private async toUserResponseDTO(user: User): Promise<UserResponseDTO> {
        const categories = await this.getUserCategories(user.id);
        return {
            id: user.id,
            name: user.name,
            email: user.email,
            crn: user.crn,
            businessName: user.businessName,
            role: AppUserRole[user.role], // cast the prisma enum to our app enum (ts file found on src/enums/)
            city: user.city,
            pfpUrl: user.pfpUrl || undefined,
            categories,
            isEmailVerified: user.isEmailVerified,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt,
        };
    }

    /**
     * Retrieves a user by their email address.
     * @param {string} email - The email of the user to retrieve.
     * @throws {NotFoundException} If the user with the given email is not found.
     * @returns {Promise<UserResponseDTO>} The found user in DTO format.
     */
    async getUserByEmail(email: string): Promise<UserResponseDTO> {
        // Check if a user exists with the given email
        // Return the user if found, otherwise return null (404 Not Found)
        const user = await this.prisma.user.findUnique({
            where: { email },
        });
        if (!user) {
            throw new NotFoundException(`User with email ${email} not found`);
        }
        return this.toUserResponseDTO(user);
    }

    /**
     * Retrieves a user by their CRN (Commercial Registration Number).
     * @param {string} crn - The CRN of the user to retrieve.
     * @throws {NotFoundException} If the user with the given CRN is not found.
     * @returns {Promise<UserResponseDTO>} The found user in DTO format.
     */
    async getUserByCRN(crn: string): Promise<UserResponseDTO> {
        const user = await this.prisma.user.findUnique({
            where: { crn },
        });
        if (!user) {
            throw new NotFoundException(`User with CRN ${crn} not found`);
        }
        return this.toUserResponseDTO(user);
    }

    /**
     * Searches for users by name using a case-insensitive partial match.
     * @param {string} name - The name or partial name to search for.
     * @throws {NotFoundException} If no users match the search criteria.
     * @returns {Promise<UserResponseDTO[]>} A list of matching users in DTO format.
     */
    async getUserByName(name: string): Promise<UserResponseDTO[]> {
        const users = await this.prisma.user.findMany({
            where: { name: { contains: name, mode: 'insensitive' } },
        });
        if (users.length === 0) {
            throw new NotFoundException(
                `No users found matching name: ${name}`,
            );
        }
        return Promise.all(users.map((user) => this.toUserResponseDTO(user)));
    }

    /**
     * Retrieves the current user's data by their ID.
     * @param {string} id - The ID of the user to retrieve.
     * @throws {NotFoundException} If the user is not found.
     * @returns {Promise<UserResponseDTO>} The user data in DTO format.
     */
    async getCurrentUserData(id: string): Promise<UserResponseDTO> {
        const user = await this.prisma.user.findUnique({
            where: { id },
        });
        if (!user) {
            throw new NotFoundException('User data not found');
        }
        return this.toUserResponseDTO(user);
    }

    /**
     * Updates the currently authenticated user's profile data.
     *
     * This method:
     * - Validates and updates the user's name, email, business name, city, and password.
     * - Sends an email verification if the email is changed.
     * - Encrypts the password if a new one is provided.
     * - Replaces the user's category associations if new ones are provided.
     *
     * @param {UpdateUserDto} dto - Data Transfer Object containing the user's update data.
     * @param {string} id - The ID of the user to update.
     * @returns {Promise<UserResponseDTO>} A promise that resolves to the updated user response DTO.
     *
     * @throws {NotFoundException} If the user with the given ID does not exist.
     * @throws {BadRequestException} If any of the provided category names are invalid.
     */
    async updateCurrentUserData(
        dto: UpdateUserDto,
        id: string,
    ): Promise<UserResponseDTO> {
        const user = await this.prisma.user.findUnique({
            where: { id },
            include: {
                categories: {
                    include: { category: true },
                },
            },
        });
        if (!user) {
            throw new NotFoundException('User not found');
        }

        let hashedPassword = user.password; // Default to existing password
        let categories: number[] = user.categories.map((c) => c.categoryId); // Default to existing categories
        if (dto.email && dto.email !== user.email) {
            const token = await this.auth.generateEmailVerificationToken(
                user.id,
                user.email,
            );
            await this.auth.sendVerificationEmail(user.email, token);
        }
        if (dto.newPassword) {
            hashedPassword = await this.auth.encryptPassword(dto.newPassword);
        }
        if (dto.categories && dto.categories.length > 0) {
            categories = await this.validateUserCategories(dto.categories);
        }

        // Update the categories of the user (by replacing the existing ones)
        await this.prisma.userCategory.deleteMany({
            where: { userId: id },
        });

        await this.prisma.userCategory.createMany({
            data: categories.map((categoryId) => ({
                userId: id,
                categoryId,
            })),
        });

        // Update the user with the data found in the dto (if no data is found in a feild, it will not be updated)
        const updatedUser = await this.prisma.user.update({
            where: { id },
            data: {
                ...(dto.name && { name: dto.name }),
                ...(dto.email && { email: dto.email }),
                ...(dto.businessName && { businessName: dto.businessName }),
                ...(dto.city && { city: dto.city }),
                password: hashedPassword, // already conditionally handled earlier
            },
            include: {
                categories: {
                    include: { category: true }, // include category info via UserCategory
                },
            },
        });

        return this.toUserResponseDTO(updatedUser);
    }

    /**
     * Validates a list of category names by checking if they exist in the database.
     * Converts valid category names into their corresponding IDs.
     *
     * @private
     * @param {string[]} payload - Array of category names to validate.
     * @throws {BadRequestException} If any of the category names do not exist in the database.
     * @returns {Promise<number[]>} Array of corresponding category IDs.
     */
    private async validateUserCategories(payload: string[]): Promise<number[]> {
        // Validate that the recieved categories exists in DB, and convert them to IDs to store them later
        const categories = await this.prisma.category.findMany({
            where: { name: { in: payload } },
        });
        if (categories.length !== payload.length) {
            const foundNames = categories.map((c) => c.name);
            const missing = payload.filter(
                (name) => !foundNames.includes(name),
            );
            throw new BadRequestException(
                `These categories are invalid: ${missing.join(', ')}`,
            );
        }
        return categories.map((c) => c.id);
    }

    /**
     * Retrieves all category names associated with a given user.
     *
     * @private
     * @param {string} userId - The ID of the user whose categories are being fetched.
     * @throws {NotFoundException} If the user is not found in the database.
     * @returns {Promise<string[]>} Array of category names linked to the user.
     */
    private async getUserCategories(userId: string): Promise<string[]> {
        const userWithCategories = await this.prisma.user.findUnique({
            where: { id: userId },
            include: { categories: { include: { category: true } } },
        });

        if (!userWithCategories) {
            throw new NotFoundException(
                'User not found when fetching categories',
            );
        }

        return userWithCategories.categories.map((uc) => uc.category.name);
    }
}
