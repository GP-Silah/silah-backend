import { UserService } from '../user/user.service';
import {
    BadRequestException,
    forwardRef,
    Inject,
    Injectable,
    InternalServerErrorException,
    NotFoundException,
} from '@nestjs/common';
import { SignupDto } from './dtos/signup.dto';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { LoginDto } from './dtos/login.dto';
import * as crypto from 'crypto';
import { ResetPasswordDto } from './dtos/resetPassword.dto';
import { UserRole } from '../enums/userRole.enum';
import { Request, Response } from 'express';
import { TapPaymentsService } from 'src/tap-payments/tap-payments.service';
import { WathqService } from 'src/wathq/wathq.service';
import { ChangePasswordDto } from './dtos/changePassword.dto';
import { Languages } from '@prisma/client';
import { EmailDto } from './dtos/email.dto';
import * as sgMail from '@sendgrid/mail';

sgMail.setApiKey(process.env.SENDGRID_API_KEY!);

/**
 * AuthService contains all authentication-related business logic,
 * such as signup, password hashing, validation, and JWT generation.
 */

@Injectable()
export class AuthService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly jwtService: JwtService,
        @Inject(forwardRef(() => UserService))
        private readonly userService: UserService,
        private readonly tapPaymentsService: TapPaymentsService,
        private readonly wathqService: WathqService,
    ) {}

    /**
     * Hashes a plain-text password using bcrypt.
     *
     * @param {string} plainText - The raw password to hash.
     * @param {number} saltRounds - The cost factor for hashing. Default is 10.
     * @returns {Promise<string>} A hashed password string.
     */
    async encryptPassword(
        // this is not a private function because it is used in the user service
        plainText: string,
        saltRounds: number = 10,
    ): Promise<string> {
        return await bcrypt.hash(plainText, saltRounds);
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
        // Validate categories: must exist & must be main (no parentCategoryId)
        const categories = await this.prisma.category.findMany({
            where: {
                id: { in: payload.categories },
                parentCategoryId: null, // ensures only main categories
            },
        });

        if (categories.length !== payload.categories.length) {
            const foundIds = categories.map((c) => c.id);
            const missing = payload.categories.filter(
                (id) => !foundIds.includes(id),
            );
            throw new BadRequestException(
                `These categories are invalid or not main categories: ${missing.join(', ')}`,
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

        // // Validate CRN is real and active via Wathq API
        // const wathqRes = await this.wathqService.getBasicInfo(payload.crn);
        // console.log(wathqRes);

        // if (!wathqRes) {
        //     throw new BadRequestException(
        //         'The provided CRN does not exist in Wathq records',
        //     );
        // }

        // // Ensure it's active (status name in Arabic or English)
        // const status = wathqRes.status?.name?.trim();
        // if (status !== 'فعال' && status.toLowerCase() !== 'active') {
        //     throw new BadRequestException(
        //         `The CRN exists but is not active (status: ${status})`,
        //     );
        // }

        // Create a Customer on Tap Payments API of the user
        const tapCustomerId = await this.tapPaymentsService.createCustomer({
            first_name: payload.name,
            email: payload.email,
        });

        // Hash the password and store the user in DB
        const hashedPassword = await this.encryptPassword(payload.password);
        const user = await this.prisma.user.create({
            data: {
                ...payload,
                tapCustomerId,
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
        await this.userService.generateDefaultAvatar(user.email);
        await this.prisma.buyer.create({
            data: {
                userId: user.id,
            },
        });
        await this.prisma.notificationPreference.create({
            data: {
                userId: user.id,
            },
        });

        // Generate a JWT token for email verification and send it via email
        const emailToken = this.generateEmailVerificationToken(
            user.id,
            user.email,
        );
        this.sendVerificationEmail(
            payload.email,
            (await emailToken).toString(),
        );

        // Generate a JWT token and return it to the controller so it sends it as a cookie
        const token = await this.jwtService.signAsync({
            sub: user.id, // Standard JWT subject claim
            email: user.email, // Useful for some identity checks
            role: user.role, // For role-based access
            isVerified: user.isEmailVerified, // For verified-only access
            jti: crypto.randomUUID(),
        });
        return { token };
    }

    /**
     * Generates a JWT token for email verification.
     *
     * @param {string} id - The user's ID.
     * @param {string} email - The user's email address.
     * @returns {Promise<string>} A signed JWT token.
     */
    async generateEmailVerificationToken(
        // this is not a private function because it is used in the user service
        id: string,
        email: string,
    ): Promise<string> {
        return await this.jwtService.signAsync({
            sub: id,
            email,
            jti: crypto.randomUUID(),
        });
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
        // this is not a private function because it is used in the user service
        const verifyUrl = `${process.env.FRONTEND_URL}/verify-email?token=${token}`;

        // Get user langauge preference
        const lang = await this.prisma.user.findUnique({
            where: { email },
            select: { preferredLanguage: true },
        });

        let mailOptions = {
            from: `"Silah Support" <${process.env.MAIL_USER}>`,
            to: email,
            subject: 'Verify your email address',
            html: `
  <div style="
      font-family: Arial, sans-serif;
      color: #000000;
      text-align: center;
      background-color: #ffffff;
      padding: 30px;
  ">
  <img src="https://silah.site/logo.png" alt="Silah Logo" width="120" style="margin-bottom: 20px;" />
    <h2 style="color: #000000; margin-bottom: 20px;">Welcome to <span style="color:#543361;">Silah</span>!</h2>
    <p style="color: #000000; font-size: 16px; margin-bottom: 25px;">
      Please verify your email address by clicking the button below:
    </p>

    <a href="${verifyUrl}" 
      style="
        display: inline-block;
        padding: 12px 25px;
        background-color: #543361;
        color: #ffffff;
        font-weight: bold;
        text-decoration: none;
        border-radius: 6px;
      ">
      Verify Email
    </a>

    <p style="color: #000000; margin-top: 30px; font-size: 14px;">
      If the button doesn't work, copy and paste the following link in your browser:
    </p>

    <p style="color: #000000; font-size: 14px; word-break: break-all;">
      <a href="${verifyUrl}" style="color: #543361; text-decoration: none;">${verifyUrl}</a>
    </p>

    <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;" />

    <small style="color: #555555; font-size: 12px;">
      This is an automated message. Please do not reply.
    </small>
  </div>
  `,
        };

        if (lang && lang.preferredLanguage === Languages.AR) {
            mailOptions = {
                from: `"Silah Support" <${process.env.MAIL_USER}>`,
                to: email,
                subject:
                    'Verify your email address | تحقق من عنوان بريدك الإلكتروني',
                html: `
  <div style="
      font-family: Arial, sans-serif;
      color: #000000;
      text-align: center;
      background-color: #ffffff;
      padding: 30px;
  ">
  <img src="https://silah.site/logo.png" alt="Silah Logo" width="120" style="margin-bottom: 20px;" />
    <h2 style="color: #000000; margin-bottom: 20px;">
      Welcome to <span style="color:#543361;">Silah</span>!
    </h2>
    <h3 dir="rtl" style="color: #000000; margin-top: 0; font-weight: normal;">
      مرحبًا بك في <span style="color:#543361;">صلة</span>!
    </h3>

    <p style="color: #000000; font-size: 16px; margin-bottom: 25px;">
      Please verify your email address by clicking the button below:
    </p>
    <p dir="rtl" style="color: #000000; font-size: 15px; margin-top: -10px; margin-bottom: 25px;">
      يرجى تأكيد عنوان بريدك الإلكتروني من خلال النقر على الزر أدناه:
    </p>

    <a href="${verifyUrl}" 
      style="
        display: inline-block;
        padding: 12px 25px;
        background-color: #543361;
        color: #ffffff;
        font-weight: bold;
        text-decoration: none;
        border-radius: 6px;
      ">
      Verify Email
    </a>
    <p dir="rtl" style="color: #000000; margin-top: 8px; font-size: 14px;">
      تأكيد البريد الإلكتروني
    </p>

    <p style="color: #000000; margin-top: 30px; font-size: 14px;">
      If the button doesn't work, copy and paste the following link in your browser:
    </p>
    <p dir="rtl" style="color: #000000; font-size: 14px; margin-top: -10px;">
      إذا لم يعمل الزر، انسخ الرابط التالي وضعه في متصفحك:
    </p>

    <p style="color: #000000; font-size: 14px; word-break: break-all;">
      <a href="${verifyUrl}" style="color: #543361; text-decoration: none;">${verifyUrl}</a>
    </p>

    <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;" />

    <small style="color: #555555; font-size: 12px;">
      This is an automated message. Please do not reply.
    </small>
    <br />
    <small dir="rtl" style="color: #555555; font-size: 12px;">
      هذه رسالة تلقائية، يُرجى عدم الرد عليها.
    </small>
  </div>
  `,
            };
        }

        try {
            const info = await sgMail.send(mailOptions);
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
    private async sendResetPasswordEmail(email: string, token: string) {
        const resetUrl = `${process.env.FRONTEND_URL}/password-reset?token=${token}`;

        // Get user langauge preference
        const lang = await this.prisma.user.findUnique({
            where: { email },
            select: { preferredLanguage: true },
        });

        let mailOptions = {
            from: `"Silah Support" <${process.env.MAIL_USER}>`,
            to: email,
            subject: 'Reset Your Silah Account Password',
            html: `
        <img src="https://silah.site/logo.png" alt="Silah Logo" width="120" style="margin-bottom: 20px;" />
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

        if (lang && lang.preferredLanguage === Languages.AR) {
            mailOptions = {
                from: `"Silah Support" <${process.env.MAIL_USER}>`,
                to: email,
                subject:
                    'Reset Your Silah Account Password | إعادة تعيين كلمة مرور حسابك في صلة',
                html: `
  <div style="
      font-family: Arial, sans-serif;
      color: #000000;
      text-align: center;
      background-color: #ffffff;
      padding: 30px;
  ">
  <img src="https://silah.site/logo.png" alt="Silah Logo" width="120" style="margin-bottom: 20px;" />
    <h2 style="color: #000000; margin-bottom: 20px;">
      Reset Your Password
    </h2>
    <h3 dir="rtl" style="color: #000000; margin-top: 0; font-weight: normal;">
      إعادة تعيين كلمة المرور
    </h3>

    <p style="color: #000000; font-size: 16px; margin-bottom: 15px;">
      We received a request to reset your Silah account password.
    </p>
    <p dir="rtl" style="color: #000000; font-size: 15px; margin-top: -10px; margin-bottom: 25px;">
      تلقّينا طلبًا لإعادة تعيين كلمة مرور حسابك في <span style="color:#543361;">صلة</span>.
    </p>

    <p style="color: #000000; font-size: 16px; margin-bottom: 25px;">
      Click the button below to reset your password. This link is valid for <strong>5 minutes</strong> only.
    </p>
    <p dir="rtl" style="color: #000000; font-size: 15px; margin-top: -10px; margin-bottom: 25px;">
      انقر على الزر أدناه لإعادة تعيين كلمة المرور. هذا الرابط صالح لمدة <strong>5 دقائق</strong> فقط.
    </p>

    <a href="${resetUrl}" 
      style="
        display: inline-block;
        padding: 12px 25px;
        background-color: #543361;
        color: #ffffff;
        font-weight: bold;
        text-decoration: none;
        border-radius: 6px;
      ">
      Reset Password
    </a>
    <p dir="rtl" style="color: #000000; margin-top: 8px; font-size: 14px;">
      إعادة تعيين كلمة المرور
    </p>

    <p style="color: #000000; margin-top: 30px; font-size: 14px;">
      If the button doesn't work, copy and paste the following link into your browser:
    </p>
    <p dir="rtl" style="color: #000000; font-size: 14px; margin-top: -10px;">
      إذا لم يعمل الزر، انسخ الرابط التالي وضعه في متصفحك:
    </p>

    <p style="color: #000000; font-size: 14px; word-break: break-all;">
      <a href="${resetUrl}" style="color: #543361; text-decoration: none;">${resetUrl}</a>
    </p>

    <p style="color: #000000; font-size: 14px; margin-top: 30px;">
      If you did not request a password reset, you can safely ignore this email.
    </p>
    <p dir="rtl" style="color: #000000; font-size: 14px; margin-top: -10px;">
      إذا لم تطلب إعادة تعيين كلمة المرور، يمكنك تجاهل هذه الرسالة بأمان.
    </p>

    <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;" />

    <small style="color: #555555; font-size: 12px;">
      This is an automated message. Please do not reply.
    </small>
    <br />
    <small dir="rtl" style="color: #555555; font-size: 12px;">
      هذه رسالة تلقائية، يُرجى عدم الرد عليها.
    </small>
  </div>
  `,
            };
        }

        try {
            const info = await sgMail.send(mailOptions);
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
            throw new BadRequestException(
                'Invalid or expired verification token',
            );
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
            throw new BadRequestException(
                'Invalid or expired reset password token',
            );
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
     * @param {string} email - The user's email address to resend the verification email to.
     *
     * @returns {{ message: string }} A confirmation message that the email was resent.
     *
     * @throws {NotFoundException} If no user with the given email is found.
     * @throws {BadRequestException} If the user's email is already verified.
     */
    async resendVerificationEmail(dto: EmailDto) {
        const email = dto.email;
        const user = await this.prisma.user.findUnique({
            where: { email },
        });
        if (!user) {
            throw new NotFoundException('User not found');
        }
        if (user.isEmailVerified) {
            throw new BadRequestException('Email already verified');
        }

        // Generate a JWT token for email verification and send it via email
        const emailToken = await this.jwtService.signAsync({
            sub: user.id,
            email,
            jti: crypto.randomUUID(),
        });
        await this.sendVerificationEmail(email, emailToken);

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
            isVerified: user.isEmailVerified, // For verified-only accesss
            jti: crypto.randomUUID(),
        });
        return { token, role: user.role };
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
     * @param {string} email - The email address to send the reset link to.
     *
     * @returns {{ message: string }} A success message indicating that the email was sent (if applicable).
     */
    async requestPasswordReset(dto: EmailDto) {
        const email = dto.email;
        // Check if the user exists in the database
        const user = await this.prisma.user.findUnique({
            where: { email },
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
        const { sub: userId, email, role: currentRole, isVerified } = tokenData;

        let newRole;
        if (currentRole === UserRole.BUYER) {
            newRole = UserRole.SUPPLIER;

            // If this is the frst time the user is switching to SUPPLIER,
            // we need to create a supplier account for them
            const existingSupplier = await this.prisma.supplier.findUnique({
                where: { userId },
            });
            if (!existingSupplier) {
                await this.prisma.supplier.create({ data: { userId } });
            }
        } else if (currentRole === UserRole.SUPPLIER) {
            newRole = UserRole.BUYER;
        } else {
            throw new InternalServerErrorException(
                'Unexpected role: GUEST should never reach this endpoint',
            );
        }

        // Change the user's role in the DB
        await this.prisma.user.update({
            where: { id: userId },
            data: { role: newRole },
        });

        // Generate new JWT
        const newToken = await this.jwtService.signAsync({
            sub: userId,
            email,
            role: newRole,
            isVerified,
        });

        // Overwrite the token cookie
        res.cookie('token', newToken, {
            httpOnly: true,
        });

        return { message: 'Role switched successfully', newRole };
    }

    async changePassword(userId: string, dto: ChangePasswordDto) {
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
        });

        if (!user) {
            throw new NotFoundException('User not found');
        }

        const isMatch = await bcrypt.compare(dto.oldPassword, user.password);
        if (!isMatch) {
            throw new BadRequestException('Current password is incorrect');
        }

        const hashedPassword = await this.encryptPassword(dto.newPassword);

        await this.prisma.user.update({
            where: { id: userId },
            data: { password: hashedPassword },
        });

        return {
            message: 'Password updated successfully.',
        };
    }
}
