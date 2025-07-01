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
import { ResetPasswordDto } from './dtos/resetPassword.dto';
import { RequestToSendEmailDto } from './dtos/requestToSendEmail.dto';
import { UserRole } from 'src/enums/userRole';
import { Request, Response } from 'express';

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
    //TODO: Validate CRN through WatheqAPI; Probably at DTO level

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
      <hr />
      <small>This is an automated message. Please do not reply.</small>
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
   * Sends a reset password email to the user with a JWT-based reset link.
   *
   * @param {string} email - The recipient's email address.
   * @param {string} token - A JWT token used to authenticate the password reset request.
   *
   * @throws {InternalServerErrorException} Thrown if sending the reset password email fails due to transport or configuration errors.
   */
  async sendResetPasswordEmail(email: string, token: string) {
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;

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
      subject: 'Reset Your Silah Account Password',
      html: `
        <h2>Reset Your Password</h2>
        <p>We received a request to reset your Silah account password.</p>
        <p>Click the button below to reset your password. This link is valid for <strong>5 minutes</strong> only.</p>
        <a href="${resetUrl}" style="display:inline-block; padding:10px 20px; background-color:#543361; color:white; text-decoration:none; border-radius:4px;">Reset Password</a>
        <p>If the button doesn't work, copy and paste the following link into your browser:</p>
        <p>${resetUrl}</p>
        <p>If you did not request a password reset, you can safely ignore this email.</p>
        <hr />
        <small>This is an automated message. Please do not reply.</small>
      `,
    };

    try {
      const info = await transporter.sendMail(mailOptions);
      console.log('Email sent:', info.response);
    } catch (error) {
      console.error('Error sending email:', error);
      throw new InternalServerErrorException(
        'Failed to send reset password email',
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
   * Resets the password of a user using a provided JWT token and a new password.
   *
   * - Verifies the reset password JWT token.
   * - Ensures the user exists.
   * - Hashes and updates the user's password.
   *
   * @param {string} resetToken - The JWT token sent to the user's email for password reset.
   * @param {ResetPasswordDto} payload - DTO containing the new password.
   *
   * @returns {{ message: string }} A success message confirming password reset.
   *
   * @throws {BadRequestException} If the token is invalid or expired.
   * @throws {NotFoundException} If the user does not exist.
   */
  async resetPassword(resetToken: string, payload: ResetPasswordDto) {
    // Verify the JWT token
    let decodedToken;
    try {
      decodedToken = await this.jwtService.verifyAsync(resetToken);
    } catch (error) {
      throw new BadRequestException('Invalid or expired reset password token');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: decodedToken.sub },
    });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Hash the new password
    const hashedPassword = await this.encryptPassword(payload.newPassword);

    // Update the user's password in the database
    await this.prisma.user.update({
      where: { id: user.id },
      data: { password: hashedPassword },
    });

    return { message: 'Password reset successfully' };
  }

  /**
   * Generates a new email verification token and sends a verification email.
   *
   * - Validates the existence of the user and their unverified email status.
   * - Generates a new JWT token and sends it via email.
   *
   * @param {RequestToSendEmailDto} payload - The user's email address to resend the verification email to.
   *
   * @returns {{ message: string }} A confirmation message that the email was resent.
   *
   * @throws {NotFoundException} If no user with the given email is found.
   * @throws {BadRequestException} If the user's email is already verified.
   */
  async resendVerificationEmail(payload: RequestToSendEmailDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: payload.email },
    });
    if (!user) {
      throw new NotFoundException('User not found');
    }
    if (user.isEmailVerified) {
      throw new BadRequestException('Email already verified');
    }

    // Generate a JWT token for email verification and send it via email
    const emailToekn = await this.jwtService.signAsync({
      sub: user.id,
      email: payload.email,
      jti: crypto.randomUUID(),
    });
    this.sendVerificationEmail(payload.email, emailToekn);

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

  /**
   * Handles a password reset request by generating a JWT token and sending it to the user's email.
   *
   * - Checks if the user exists and their email is verified.
   * - Generates a short-lived JWT reset token (5 minutes).
   * - Sends the reset password email with the token.
   *
   * For security reasons, this method returns silently even if the user does not exist or their email is not verified.
   *
   * @param {RequestToSendEmailDto} payload - The email address to send the reset link to.
   *
   * @returns {{ message: string }} A success message indicating that the email was sent (if applicable).
   */
  async requestPasswordReset(payload: RequestToSendEmailDto) {
    // Check if the user exists in the database
    const user = await this.prisma.user.findUnique({
      where: { email: payload.email },
    });
    if (!user || !user.isEmailVerified) return; // for security reasons, we don't reveal if the user exists

    // Generate a JWT token for password reset and send it via email
    const resetToken = await this.jwtService.signAsync(
      {
        sub: user.id,
        email: user.email,
        jti: crypto.randomUUID(),
      },
      { expiresIn: '5m' },
    ); // Token expires in 5 minutes
    await this.sendResetPasswordEmail(user.email, resetToken);

    return { message: 'Password reset email sent successfully' };
  }

  async switchUserRole(req: Request, res: Response) {
    const tokenData = req.tokenData!;
    const { sub: userId, email, role: currentRole } = tokenData;

    let newRole;
    if (currentRole === UserRole.BUYER) newRole = UserRole.SUPPLIER;
    else if (currentRole === UserRole.SUPPLIER) newRole = UserRole.BUYER;
    else
      throw new InternalServerErrorException(
        'Unexpected role: GUEST should never reach this endpoint',
      );

    // Generate new JWT
    const newToken = await this.jwtService.signAsync({
      sub: userId,
      email,
      role: newRole,
    });

    // Overwrite the token cookie
    res.cookie('token', newToken, {
      httpOnly: true,
    });

    return { message: 'Role switched successfully', newRole };
  }
}
