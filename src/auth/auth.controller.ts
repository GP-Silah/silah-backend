import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('sign-up')
  async signUp() {}

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
