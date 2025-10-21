import {
    Body,
    Controller,
    Patch,
    Post,
    Query,
    Req,
    Res,
    UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { Response } from 'express';
import { SignupDto } from './dtos/signup.dto';
import { ApiTags } from '@nestjs/swagger';
import { LoginDto } from './dtos/login.dto';
import { ResetPasswordDto } from './dtos/resetPassword.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { ApiDocsJwtAuthGuard } from './decorators/jwt-auth-guard.docs';
import { Request } from 'express';
import {
    ApiDocsChangePassword,
    ApiDocsLogin,
    ApiDocsLogout,
    ApiDocsRequestPasswordReset,
    ApiDocsResendVerificationEmail,
    ApiDocsResetPassword,
    ApiDocsSignUp,
    ApiDocsSwitchRole,
    ApiDocsVerifyEmail,
} from './auth.docs';
import { ApiDocsVerifiedGuard } from './decorators/verified-guard.docs';
import { VerifiedGuard } from './guards/verified.guard';
import { ChangePasswordDto } from './dtos/changePassword.dto';
import { EmailDto } from './dtos/email.dto';

/**
 * AuthController handles incoming authentication-related requests,
 * such as user signup, and delegates logic to AuthService.
 */

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    /**
     * Registers a new user and returns a JWT token in a cookie.
     *
     * @param {SignupDto} dto - The data required for user registration.
     * @param {Response} res - The Express response object to set the cookie.
     * @returns {{ message: string }} A success message indicating registration succeeded.
     */
    @Post('signup')
    @ApiDocsSignUp()
    async signUp(
        @Body() dto: SignupDto,
        @Req() req: Request,
        @Res({ passthrough: true }) res: Response,
    ) {
        const token = await this.authService.signUp(dto);
        const isCrossSite = req.hostname !== 'localhost'; // backend is prod
        const isSecure =
            req.secure || req.headers['x-forwarded-proto'] === 'https';
        res.cookie('token', token, {
            httpOnly: true,
            secure: isCrossSite ? true : isSecure, // force secure for cross-site
            sameSite: isCrossSite ? 'none' : 'lax', // must be 'none' for cross-site
            path: '/',
        });
        return { message: 'Signup successful' };
    }

    @Post('login')
    @ApiDocsLogin()
    async login(
        @Body() dto: LoginDto,
        @Req() req: Request,
        @Res({ passthrough: true }) res: Response,
    ) {
        const token = await this.authService.login(dto);
        const isCrossSite = req.hostname !== 'localhost'; // backend is prod
        const isSecure =
            req.secure || req.headers['x-forwarded-proto'] === 'https';
        res.cookie('token', token, {
            httpOnly: true,
            secure: isCrossSite ? true : isSecure, // force secure for cross-site
            sameSite: isCrossSite ? 'none' : 'lax', // must be 'none' for cross-site
            path: '/',
        });
        return { message: 'Login successful' };
    }

    @Post('/logout')
    @ApiDocsLogout()
    logout(@Res({ passthrough: true }) res: Response) {
        res.clearCookie('token');
        res.send('Successfully logged out');
    }

    // After signup the system will send an email with a verification link to the user's email address.
    // The user needs to click on the link to go to a page where they click a button to verify it,that is when this route is called.
    @Post('verify-email')
    @ApiDocsVerifyEmail()
    async verifyEmail(@Query('token') token: string) {
        return await this.authService.verifyEmail(token);
    }

    // In case the user missed the mail or the token expired, the frontend can call this route to resend the verification email.
    @Post('resend-verification-email')
    @ApiDocsResendVerificationEmail()
    async resendVerificationEmail(@Body() email: EmailDto) {
        return await this.authService.resendVerificationEmail(email);
    }

    @Post('request-password-reset')
    @ApiDocsRequestPasswordReset()
    async requestPasswordReset(@Body() email: EmailDto) {
        return await this.authService.requestPasswordReset(email);
    }

    @Post('reset-password')
    @ApiDocsResetPassword()
    async resetPassword(
        @Query('token') token: string,
        @Body() dto: ResetPasswordDto,
    ) {
        return await this.authService.resetPassword(token, dto);
    }

    @ApiDocsJwtAuthGuard()
    @UseGuards(JwtAuthGuard)
    @Patch('switch-role')
    @ApiDocsSwitchRole()
    async switchUserRole(
        @Req() req: Request,
        @Res({ passthrough: true }) res: Response,
    ) {
        return await this.authService.switchUserRole(req, res);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsVerifiedGuard()
    @UseGuards(JwtAuthGuard, VerifiedGuard)
    @Patch('me/change-password')
    @ApiDocsChangePassword()
    async changePassword(@Req() req: Request, @Body() dto: ChangePasswordDto) {
        return this.authService.changePassword(req.tokenData!.sub, dto);
    }
}
