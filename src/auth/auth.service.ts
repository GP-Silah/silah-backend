import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import { SignupDto } from './dtos/signup.dto';
import * as bcrypt from 'bcrypt';
import { PrismaService } from 'src/prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { LoginDto } from './dtos/login.dto';
import { TokenType } from 'src/enums/tokenType';
import * as crypto from 'crypto';
import { Cron, CronExpression } from '@nestjs/schedule';

/**
 * AuthService contains all authentication-related business logic,
 * such as signup, password hashing, validation, and JWT generation.
 */

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  /**
   * Hashes a plain-text password using bcrypt.
   *
   * @param {string} plainText - The raw password to hash.
   * @param {number} saltRounds - The cost factor for hashing. Default is 10.
   * @returns {Promise<string>} A hashed password string.
   */
  async encryptPassword(
    plainText: string,
    saltRounds: number = 10,
  ): Promise<string> {
    return await bcrypt.hash(plainText, saltRounds);
  }

  /**
   * Compares a hashed password with a plain-text password.
   *
   * @param {string} hashedPassword - The stored hashed password.
   * @param {string} plainText - The input password to compare.
   * @returns {Promise<boolean>} A boolean indicating if the passwords match.
   */
  async comparePasswords(
    hashedPassword: string,
    plainText: string,
  ): Promise<boolean> {
    return await bcrypt.compare(plainText, hashedPassword);
  }

  /**
   * Registers a new user in the system.
   * - Validates categories.
   * - Ensures uniqueness of NID, CRN, and email.
   * - Hashes the password.
   * - Stores the user and links categories.
   * - Returns a JWT token.
   *
   * @param {SignupDto} payload - The signup data from the user.
   * @returns {{token: string}} A JWT token to be sent to the client.
   * @throws BadRequestException if validation fails.
   */
  async signUp(payload: SignupDto): Promise<{ token: string }> {
    // Validate that the recieved categories exists in DB, and convert them to IDs to store them later
    const categories = await this.prisma.category.findMany({
      where: { name: { in: payload.categories } },
    });
    if (categories.length !== payload.categories.length) {
      const foundNames = categories.map((c) => c.name);
      const missing = payload.categories.filter(
        (name) => !foundNames.includes(name),
      );
      throw new BadRequestException(
        `These categories are invalid: ${missing.join(', ')}`,
      );
    }
    const categoryIds = categories.map((c) => c.id);

    // Insure that the NID, CRN, Email are unique in DB
    const existingUser = await this.prisma.user.findFirst({
      where: {
        OR: [
          { nid: payload.nid },
          { crn: payload.crn },
          { email: payload.email },
        ],
      },
    });
    if (existingUser) {
      if (existingUser.nid === payload.nid) {
        throw new BadRequestException('NID already exists');
      }
      if (existingUser.crn === payload.crn) {
        throw new BadRequestException('CRN already exists');
      }
      if (existingUser.email === payload.email) {
        throw new BadRequestException('Email already exists');
      }
    }

    // Hash the password and store the user in DB
    const hashedPassword = await this.encryptPassword(payload.password);
    const user = await this.prisma.user.create({
      data: {
        ...payload,
        password: hashedPassword,
        categories: {
          create: categoryIds.map((categoryId) => ({
            category: {
              connect: { id: categoryId },
            },
          })),
        },
      },
    });

    // Generate a JWT token and return it to the controller so it sends it as a cookie
    const token = await this.jwtService.signAsync({
      sub: user.id, // Standard JWT subject claim
      email: user.email, // Useful for some identity checks
      role: user.role, // For role-based access
    });
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24); // 1 day
    await this.prisma.userToken.create({
      data: {
        userId: user.id,
        token: hashedToken,
        tokenType: TokenType.TOKEN,
        expiresAt,
      },
    });
    return { token };
  }

  async login(payload: LoginDto) {
    // Check if the user exists in the database
    const user = await this.prisma.user.findFirst({
      where: {
        OR: [{ email: payload.email }, { crn: payload.crn }],
      },
    });
    if (!user) {
      throw new BadRequestException('User not found');
    }
    // Compare between the entered password with the hashed password stored in DB
    // If the passwords match, generate a JWT token and return it to the controller so it sends it as a cookie
    const checkPasswords = await bcrypt.compare(
      payload.password,
      user.password,
    );
    if (!checkPasswords) {
      throw new BadRequestException('Invalid credentials');
    }
    const token = await this.jwtService.signAsync({
      sub: user.id, // Standard JWT subject claim
      email: user.email, // Useful for some identity checks
      role: user.role, // For role-based access
    });
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24); // 1 day
    await this.prisma.userToken.create({
      data: {
        userId: user.id,
        token: hashedToken,
        tokenType: TokenType.TOKEN,
        expiresAt,
      },
    });
    return { token };
  }

  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async cleanUpExpiredTokens() {
    const now = new Date();

    const result = await this.prisma.userToken.deleteMany({
      where: {
        OR: [{ isUsed: true }, { expiresAt: { lt: now } }],
      },
    });

    this.logger.log(
      `Deleted ${result.count} expired/used tokens at ${now.toISOString()}`,
    );
  }
}
