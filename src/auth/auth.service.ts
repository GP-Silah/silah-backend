import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import { SignupDto } from './dtos/signup.dto';
import * as bcrypt from 'bcrypt';
import { PrismaService } from 'src/prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { LoginDto } from './dtos/login.dto';
import { TokenType } from 'src/enums/tokenType';
import * as crypto from 'crypto';
import { Cron, CronExpression } from '@nestjs/schedule';
import { User } from '@prisma/client';
import * as nodemailer from 'nodemailer';

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

  async storeToken(user: User, token: string, tokenType: TokenType) {
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    const expiration =
      tokenType === TokenType.PASSWORD_RESET
        ? new Date(Date.now() + 5 * 60 * 1000) // 5 minutes from now
        : new Date(Date.now() + 24 * 60 * 60 * 1000); // 1 day from now
    await this.prisma.userToken.create({
      data: {
        userId: user.id,
        token: hashedToken,
        tokenType,
        expiresAt: expiration,
      },
    });
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

    // Generate a JWT token for email verification and store it in DB
    const emailToekn = await this.jwtService.signAsync({
      sub: user.id,
      email: payload.email,
    });
    this.storeToken(user, emailToekn, TokenType.EMAIL_VERIFICATION);
    this.sendVerificationEmail(payload.email, emailToekn);

    // Generate a JWT token and return it to the controller so it sends it as a cookie
    const token = await this.jwtService.signAsync({
      sub: user.id, // Standard JWT subject claim
      email: user.email, // Useful for some identity checks
      role: user.role, // For role-based access
    });
    this.storeToken(user, token, TokenType.TOKEN);
    return { token };
  }

  async sendVerificationEmail(email: string, token: string) {
    const verifyUrl = `${process.env.FRONTEND_URL}/verify-email?token=${token}`;

    // Create reusable transporter object using SMTP transport
    const transporter = nodemailer.createTransport({
      host: process.env.MAIL_HOST,
      port: Number(process.env.MAIL_PORT),
      secure: process.env.MAIL_SECURE,
      auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASS,
      },
    });

    const mailOptions = {
      from: `"Silah Support" <${process.env.MAIL_USER}>`,
      to: email,
      subject: 'Verify your email address',
      html: `
      <h2>Welcome to Silah!</h2>
      <p>Please verify your email address by clicking the button below:</p>
      <a href="${verifyUrl}" style="display:inline-block; padding:10px 20px; background-color:#4CAF50; color:white; text-decoration:none; border-radius:4px;">Verify Email</a>
      <p>If the button doesn't work, copy and paste the following link in your browser:</p>
      <p>${verifyUrl}</p>
    `,
    };

    await transporter.sendMail(mailOptions);
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
    this.storeToken(user, token, TokenType.TOKEN);
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
