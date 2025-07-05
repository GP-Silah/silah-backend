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

@Injectable()
export class UserService {
  constructor(private readonly prisma: PrismaService) {}

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
      isVerified: user.isVerified,
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
      throw new NotFoundException(`No users found matching name: ${name}`);
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

  async updateCurrentUserData(
    dto: UpdateUserDto,
    id: string,
  ): Promise<UserResponseDTO> {
    const user = await this.prisma.user.findUnique({
      where: { id },
    });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const updatedUser = await this.prisma.user.update({
      where: { id },
      data: {
        name: dto.name,
        email: dto.email, //TODO Note: Email update logic should be handled separately with verification
        businessName: dto.businessName,
        city: dto.city,
        //TODO Note: Password update logic should be handled separately with hashing
      },
    });

    //TODO update the user categories
    return this.toUserResponseDTO(updatedUser);
  }

  private async handleEmailUpdate(email: string, userId: number) {}

  private async handlePasswordUpdate(password: string, userId: number) {}

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
      const missing = payload.filter((name) => !foundNames.includes(name));
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
      throw new NotFoundException('User not found when fetching categories');
    }

    return userWithCategories.categories.map((uc) => uc.category.name);
  }
}
