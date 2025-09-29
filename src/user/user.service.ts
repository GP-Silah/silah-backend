import {
    BadRequestException,
    forwardRef,
    Inject,
    Injectable,
    NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { UserResponseDTO } from './dtos/userResponse.dto';
import { Languages, User } from '@prisma/client';
import { UserRole as AppUserRole } from '../enums/userRole.enum';
import { UpdateUserDto } from './dtos/updateUser.dto';
import { AuthService } from '../auth/auth.service';
import { FileService } from '../file/file.service';
import * as sharp from 'sharp'; // converts SVG → PNG

@Injectable()
export class UserService {
    constructor(
        private readonly prisma: PrismaService,
        @Inject(forwardRef(() => AuthService))
        private readonly auth: AuthService,
        private readonly fileService: FileService,
    ) {}

    /**
     * Converts a Prisma User model into a UserResponseDTO including categories.
     *
     * @param {User} user - The user object from the database.
     * @returns {Promise<UserResponseDTO>} A user DTO formatted for responses.
     */
    async toUserResponseDTO(user: User): Promise<UserResponseDTO> {
        const categories = await this.getUserCategories(user.id);
        const pfpUrl = user.pfpFileName
            ? await this.fileService.getFileUrl(user.pfpFileName)
            : '';
        return {
            userId: user.id,
            tapCustomerId: user.tapCustomerId,
            name: user.name,
            email: user.email,
            crn: user.crn,
            businessName: user.businessName,
            role: AppUserRole[user.role], // cast the prisma enum to our app enum (ts file found on src/enums/)
            city: user.city,
            pfpFileName: user.pfpFileName || '',
            pfpUrl: pfpUrl || '',
            categories,
            isEmailVerified: user.isEmailVerified,
            preferredLanguage: user.preferredLanguage,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt,
        };
    }

    /**
     * Retrieves a user by their ID.
     * @param {string} id - The id of the user to retrieve.
     * @throws {NotFoundException} If the user with the given id is not found.
     * @returns {Promise<UserResponseDTO>} The found user in DTO format.
     */
    async getUserById(id: string): Promise<UserResponseDTO> {
        // Check if a user exists with the given id
        // Return the user if found, otherwise return null (404 Not Found)
        const user = await this.prisma.user.findUnique({
            where: { id },
        });
        if (!user) {
            throw new NotFoundException(`User with id ${id} not found`);
        }
        return this.toUserResponseDTO(user);
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
     * @throws {BadRequestException} If the name parameter is empty.
     * @throws {NotFoundException} If no users match the search criteria.
     * @returns {Promise<UserResponseDTO[]>} A list of matching users in DTO format.
     */
    async getUserByName(name: string): Promise<UserResponseDTO[]> {
        if (!name || name.trim() === '') {
            throw new BadRequestException('Name parameter is required');
        }
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
            await this.auth.sendVerificationEmail(dto.email, token);
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
     * Validates a list of category IDs by checking if they exist in the database.
     *
     * @private
     * @param {number[]} payload - Array of category IDs to validate.
     * @throws {BadRequestException} If any of the category IDs do not exist in the database.
     * @returns {Promise<number[]>} Array of valid category IDs.
     */
    private async validateUserCategories(payload: number[]): Promise<number[]> {
        // Fetch all categories matching given IDs
        const categories = await this.prisma.category.findMany({
            where: { id: { in: payload } },
        });

        if (categories.length !== payload.length) {
            const foundIds = categories.map((c) => c.id);
            const missing = payload.filter((id) => !foundIds.includes(id));
            throw new BadRequestException(
                `These categories are invalid: ${missing.join(', ')}`,
            );
        }

        return categories.map((c) => c.id);
    }

    /**
     * Retrieves all categories associated with a given user.
     *
     * @private
     * @param {string} userId - The ID of the user whose categories are being fetched.
     * @throws {NotFoundException} If the user is not found in the database.
     * @returns {Promise<{id: number, name: string}[]>} Array of categories (ID + name) linked to the user.
     */
    private async getUserCategories(
        userId: string,
    ): Promise<{ id: number; name: string }[]> {
        const userWithCategories = await this.prisma.user.findUnique({
            where: { id: userId },
            include: { categories: { include: { category: true } } },
        });

        if (!userWithCategories) {
            throw new NotFoundException(
                'User not found when fetching categories',
            );
        }

        return userWithCategories.categories.map((uc) => ({
            id: uc.category.id,
            name: uc.category.name,
        }));
    }

    /**
     * Generates a darker shade of a given HSL color string.
     * @private
     * @param {string} hsl - The HSL color string (e.g., "hsl(210, 50%, 60%)").
     * @param {number} [amount=20] - The amount to decrease the lightness by (default is 20).
     * @returns {string} The darker HSL color string.
     * If the input is invalid, returns a fallback color '#333'.
     */
    private darkerColor(hsl, amount = 20) {
        const match = hsl.match(/hsl\((\d+),\s*([\d.]+)%,\s*([\d.]+)%\)/);
        if (!match) return '#333'; // fallback
        let [_, h, s, l] = match;
        l = Math.max(0, parseFloat(l) - amount);
        return `hsl(${h}, ${s}%, ${l}%)`;
    }

    /**
     * Generates a default avatar PNG for a user based on the first letter of their name.
     * The avatar background color is deterministically chosen from a preset color palette.
     * The generated PNG is uploaded using the FileService and the user's record is updated.
     *
     * @param {string} email - The email of the user for whom to generate the avatar.
     * @returns {Promise<string>} - The file name of the uploaded default avatar.
     */
    async generateDefaultAvatar(email: string) {
        const user = await this.prisma.user.findUnique({
            where: { email },
        });
        if (!user) throw new NotFoundException('User not found');
        const base = (user.name ?? '').trim() || user.email;
        const letter = base.charAt(0).toUpperCase();
        // generate random pastel-like colors at startup
        const colors = Array.from({ length: 6 }, () => {
            const hue = Math.floor(Math.random() * 360); // 0–360 degrees
            const saturation = 60 + Math.random() * 20; // 60–80%
            const lightness = 70 + Math.random() * 10; // 70–80%
            return `hsl(${hue}, ${saturation}%, ${lightness}%)`;
        });
        const idx = base.charCodeAt(0) % colors.length;
        const bgColor = colors[idx];
        const textColor = this.darkerColor(bgColor);

        const svg = `
            <svg xmlns="http://www.w3.org/2000/svg" width="128" height="128">
            <rect width="100%" height="100%" fill="${bgColor}"/>
            <text x="50%" y="50%" font-size="64" text-anchor="middle" dy=".35em" fill="${textColor}" font-family="Georgia, serif">
                ${letter}
            </text>
            </svg>
        `;

        const buffer = Buffer.from(svg);
        const pngBuffer = await sharp(buffer).png().toBuffer();
        const fileName = `default-avatars/${user.id}`;
        const realFileName = await this.fileService.uploadFile({
            originalname: fileName,
            buffer: pngBuffer,
            mimetype: 'image/png',
            size: pngBuffer.length,
        } as Express.Multer.File);
        await this.prisma.user.update({
            where: { email },
            data: { pfpFileName: realFileName, isPfpDefault: true },
        });
        return realFileName;
    }

    /**
     * Updates a user's profile picture by uploading a new file and updating the user's record.
     *
     * @param {Express.Multer.File} file - The new profile picture file to upload.
     * @param {string} userEmail - The email of the user whose profile picture will be updated.
     * @returns {Promise<{ message: string; pfpFileName: string }>} - Confirmation message and uploaded file name.
     */
    async updateProfilePicture(file: Express.Multer.File, userEmail: string) {
        const fileName = await this.fileService.uploadFile(file);
        await this.prisma.user.update({
            where: { email: userEmail },
            data: { pfpFileName: fileName, isPfpDefault: false },
        });
        return {
            message: 'Profile picture updated successfully',
            pfpFileName: fileName,
        };
    }

    /**
     * Deletes a user's current profile picture and replaces it with a default avatar.
     *
     * @param {string} userEmail - The email of the user whose profile picture will be deleted.
     * @throws {NotFoundException} if the user does not exist or already has a default profile picture.
     * @returns {Promise<{ message: string }>} - Confirmation message of successful deletion.
     */
    async deleteProfilePicture(userEmail: string) {
        const user = await this.prisma.user.findUnique({
            where: { email: userEmail },
        });
        if (!user) {
            throw new NotFoundException('User not found');
        }
        if (user.isPfpDefault) {
            throw new BadRequestException('Profile picture already default');
        }
        // Future Work ?: Delete the file from the storage (R2)
        await this.generateDefaultAvatar(userEmail);
        return { message: 'Profile picture deleted successfully' };
    }

    /**
     * Retrieves the URL of a user's profile picture that is uploaded on R2.
     *
     * @param {string} userId - The ID of the user whose profile picture URL will be retrieved.
     * @throws {NotFoundException} if the user or profile picture does not exist.
     * @returns {Promise<{ pfpUrl: string }>} - Object containing the profile picture URL.
     */
    async getUserProfilePictureUrl(userId: string) {
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
            select: { pfpFileName: true },
        });
        if (!user || !user.pfpFileName) {
            throw new NotFoundException('Profile picture not found');
        }
        const pfpUrl = await this.fileService.getFileUrl(user.pfpFileName);
        return { pfpUrl };
    }

    /**
     * Retrieves the profile picture URLs for multiple users by their IDs.
     * Only valid UUIDs are considered.
     *
     * @param {string[]} ids - Array of user IDs to retrieve profile picture URLs for.
     *@throws {BadRequestException} if input is invalid or NotFoundException if no users are found.
     * @returns {Promise<{ id: string; pfpUrl: string | null }[]>} - Array of objects with user IDs and their profile picture URLs.
     */
    async getUsersProfilePicturesUrls(ids: string[]) {
        if (!Array.isArray(ids) || ids.length === 0) {
            throw new BadRequestException('No user IDs provided');
        }
        // Keep only valid UUIDs
        const validIds = ids.filter((id) => {
            try {
                return isUuid(id);
            } catch (e) {
                return false;
            }
        });
        if (validIds.length === 0) {
            throw new BadRequestException('No valid UUIDs provided');
        }
        const users = await this.prisma.user.findMany({
            where: { id: { in: validIds } },
            select: { id: true, pfpFileName: true },
        });
        if (users.length === 0) {
            throw new NotFoundException('No users found with the provided IDs');
        }
        const urls = await Promise.all(
            users.map(async (user) => {
                const pfpUrl = user.pfpFileName
                    ? await this.fileService.getFileUrl(user.pfpFileName)
                    : null;
                return { id: user.id, pfpUrl };
            }),
        );
        return urls;
    }

    /**
     * Switches the preferred language of a user between English (ENG) and Arabic (ARA).
     *
     * This updates the `preferredLanguage` field in the database for the given user.
     * If the user currently has English as their preferred language, it will switch to Arabic, and vice versa.
     *
     * @param {string} userEmail - The email of the user whose preferred language should be switched.
     * @returns {Promise<{ email: string; oldLanguage: Languages; newLanguage: Languages }>}
     *          An object containing the user's email, previous preferred language, and the new preferred language.
     *
     * @throws {NotFoundException} If the user with the given email does not exist.
     *
     * @example
     * const result = await userService.switchPreferredLanguage('user@example.com');
     */
    async switchPreferredLanguage(userEmail: string) {
        const user = await this.prisma.user.findUnique({
            where: { email: userEmail },
        });
        if (!user) {
            throw new NotFoundException('User not found');
        }
        const oldLanguage: Languages = user.preferredLanguage;
        const newLanguage: Languages =
            oldLanguage === Languages.EN ? Languages.AR : Languages.EN;
        await this.prisma.user.update({
            where: { email: userEmail },
            data: { preferredLanguage: newLanguage },
        });
        return {
            email: user.email,
            oldLanguage,
            newLanguage,
        };
    }
}

/**
 * Checks whether a string is a valid UUID (v1-v5).
 *
 * @param {string} id - The string to validate as a UUID.
 * @returns {boolean} - True if the string is a valid UUID, false otherwise.
 */
function isUuid(id: string): boolean {
    // UUID v4 regex (accepts v1-v5, but v4 is most common)
    try {
        return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
            id,
        );
    } catch (e) {
        return false; // Treat invalid inputs as non-UUIDs
    }
}
