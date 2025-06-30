import { Body, Controller, Post, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Response } from 'express';
import { SignupDto } from './dtos/signup.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  async signUp(
    @Body() dto: SignupDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const token = await this.authService.signUp(dto);
    res.cookie('token', token, {
      httpOnly: true,
      secure: true, // only over HTTPS in production
    });
    return { message: 'Signup successful' };
  }

  @Post('login')
  async login() {}

  @Post('logout')
  async logout() {}

  // after signup the system will send an email with a verification link to the user's email address. The user needs to click on the link to go to a page where they click a button to verify it, that is when this route is called.
  @Post('verify-email')
  async verifyEmail() {}

  @Post('request-password-reset')
  async requestPasswordReset() {}

  @Post('reset-password')
  async resetPassword() {}
}
