import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { SignupDto } from './dtos/signup.dto';
import * as bcrypt from 'bcrypt';
import { PrismaService } from 'src/prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { LoginDto } from './dtos/login.dto';
import * as crypto from 'crypto';
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

    // Generate a JWT token for email verification and send it via email
    const emailToekn = await this.jwtService.signAsync({
      sub: user.id,
      email: payload.email,
      jti: crypto.randomUUID(),
    });
    this.sendVerificationEmail(payload.email, emailToekn);

    // Generate a JWT token and return it to the controller so it sends it as a cookie
    const token = await this.jwtService.signAsync({
      sub: user.id, // Standard JWT subject claim
      email: user.email, // Useful for some identity checks
      role: user.role, // For role-based access
      jti: crypto.randomUUID(),
    });
    return { token };
  }

  /**
   * Sends an email to the user containing a verification link with a JWT token.
   *
   * @param {string} email - The email address of the user to send the verification to.
   * @param {string} token - The JWT token to be included in the verification link.
   *
   * @throws {InternalServerErrorException} Thrown if sending the email fails due to transport issues or misconfiguration.
   */
  async sendVerificationEmail(email: string, token: string) {
    const verifyUrl = `${process.env.FRONTEND_URL}/verify-email?token=${token}`;

    // Create reusable transporter object using SMTP transport
    const transporter = nodemailer.createTransport({
      host: process.env.MAIL_HOST,
      port: Number(process.env.MAIL_PORT),
      secure: process.env.MAIL_SECURE === 'true', // convert string to boolean
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
      <a href="${verifyUrl}" style="display:inline-block; padding:10px 20px; background-color:#543361; color:white; text-decoration:none; border-radius:4px;">Verify Email</a>
      <p>If the button doesn't work, copy and paste the following link in your browser:</p>
      <p>${verifyUrl}</p>
    `,
    };

    try {
      const info = await transporter.sendMail(mailOptions);
      console.log('Email sent:', info.response);
    } catch (error) {
      console.error('Error sending email:', error);
      throw new InternalServerErrorException(
        'Failed to send verification email',
      );
    }
  }

  /**
   * Verifies the email address of a user using a provided JWT token.
   *
   * - Decodes and verifies the JWT.
   * - Confirms the user exists and is not already verified.
   * - Updates the user's verification status to `true`.
   *
   * @param {string} token - The JWT token sent to the user's email.
   *
   * @returns {{ message: string }} A success message confirming email verification.
   *
   * @throws {BadRequestException} If the token is invalid or expired.
   * @throws {BadRequestException} If the user does not exist or is already verified.
   */
  async verifyEmail(token: string) {
    // Verify the JWT token
    let decodedToken;
    try {
      decodedToken = await this.jwtService.verifyAsync(token);
    } catch (error) {
      throw new BadRequestException('Invalid or expired verification token');
    }

    // Find the user by ID
    const user = await this.prisma.user.findUnique({
      where: { id: decodedToken.sub },
    });
    if (!user || user.isEmailVerified) {
      throw new BadRequestException('User not found or already verified');
    }

    // Update the user's email verification status
    await this.prisma.user.update({
      where: { id: user.id },
      data: { isEmailVerified: true },
    });

    return { message: 'Email verified successfully' };
  }

  /**
   * Generates a new email verification token and sends a verification email.
   *
   * - Validates the existence of the user and their unverified email status.
   * - Generates a new JWT token and sends it via email.
   *
   * @param {string} email - The user's email address to resend the verification email to.
   *
   * @returns {{ message: string }} A confirmation message that the email was resent.
   *
   * @throws {NotFoundException} If no user with the given email is found.
   * @throws {BadRequestException} If the user's email is already verified.
   */
  async resendVerificationEmail(email: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
      throw new NotFoundException('User not found');
    }
    if (user.isEmailVerified) {
      throw new BadRequestException('Email already verified');
    }

    // Generate a JWT token for email verification and send it via email
    const emailToekn = await this.jwtService.signAsync({
      sub: user.id,
      email,
      jti: crypto.randomUUID(),
    });
    this.sendVerificationEmail(email, emailToekn);

    return { message: 'Verification email resent successfully' };
  }

  /**
   * Authenticates a user using their email or CRN and password.
   *
   * - Validates that the user exists by email or CRN.
   * - Compares the entered password with the hashed password in the database.
   * - If valid, returns a signed JWT token.
   *
   * @param {LoginDto} payload - Contains the user's login credentials (email/CRN and password).
   *
   * @returns {{ token: string }} The signed JWT token for authenticated access.
   *
   * @throws {BadRequestException} If the user is not found.
   * @throws {BadRequestException} If the password is incorrect.
   */
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
      jti: crypto.randomUUID(),
    });
    return { token };
  }
}
