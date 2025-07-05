import {
  BadRequestException,
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
import {
  ApiTags,
  ApiResponse,
  ApiBody,
  ApiBadRequestResponse,
  ApiOperation,
  ApiQuery,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiInternalServerErrorResponse,
} from '@nestjs/swagger';
import { LoginDto } from './dtos/login.dto';
import { ResetPasswordDto } from './dtos/resetPassword.dto';
import { ParseEmailPipe } from '../pipes/parse-email.pipe';
import { JwtAuthGuard } from './guards/jwt-auth/jwt-auth.guard';
import { ApiJwtAuthGuard } from './decorators/api-jwt-auth-guard.decorator';
import { Request } from 'express';

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
  @ApiOperation({
    summary: 'Registers a new user and returns a JWT token in a cookie',
  })
  @ApiBody({ type: SignupDto })
  @ApiResponse({
    status: 201,
    description: 'User signed up successfully. JWT sent in cookie.',
    schema: {
      example: {
        message: 'Signup successful',
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Bad Request - validation or conflict',
    content: {
      'application/json': {
        schema: {
          oneOf: [
            // Optional: if you want typed schema matching different error shapes
            {
              example: {
                statusCode: 400,
                message: 'These categories are invalid: Cleaning, Laundry',
                error: 'Bad Request',
              },
            },
            {
              example: {
                statusCode: 400,
                message: 'NID already exists',
                error: 'Bad Request',
              },
            },
            {
              example: {
                statusCode: 400,
                message: 'CRN already exists',
                error: 'Bad Request',
              },
            },
            {
              example: {
                statusCode: 400,
                message: 'Email already exists',
                error: 'Bad Request',
              },
            },
          ],
        },
        examples: {
          categories: {
            summary: 'Invalid Categories',
            value: {
              statusCode: 400,
              message: 'These categories are invalid: Cleaning, Laundry',
              error: 'Bad Request',
            },
          },
          nid: {
            summary: 'NID already exists',
            value: {
              statusCode: 400,
              message: 'NID already exists',
              error: 'Bad Request',
            },
          },
          crn: {
            summary: 'CRN already exists',
            value: {
              statusCode: 400,
              message: 'CRN already exists',
              error: 'Bad Request',
            },
          },
          email: {
            summary: 'Email already exists',
            value: {
              statusCode: 400,
              message: 'Email already exists',
              error: 'Bad Request',
            },
          },
        },
      },
    },
  })
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
  @ApiOperation({
    summary: 'Login user and send back JWT token as a cookie',
    description: 'Either "email" or "crn" must be provided, but not both.',
  })
  @ApiBody({ type: LoginDto })
  @ApiResponse({
    status: 201,
    description: 'User successfully logged in',
    schema: {
      example: {
        message: 'Login successful',
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request – validation or authentication failure',
    content: {
      'application/json': {
        examples: {
          userNotFound: {
            summary: 'The user does not exist in the system',
            value: {
              statusCode: 400,
              message: 'User not found',
              error: 'Bad Request',
            },
          },
          invalidCredentials: {
            summary: 'The email or CRN exists, but the password is incorrect',
            value: {
              statusCode: 400,
              message: 'Invalid credentials',
              error: 'Bad Request',
            },
          },
        },
      },
    },
  })
  async login(
    @Body() dto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const token = await this.authService.login(dto);
    res.cookie('token', token, {
      httpOnly: true,
      secure: true, // only over HTTPS in production
    });
    return { message: 'Login successful' };
  }

  @Post('/logout')
  @ApiOperation({ summary: 'Logout user by clearing token cookie' })
  @ApiResponse({
    status: 200,
    description: 'Successfully logged out',
    schema: { example: 'Successfully logged out' },
  })
  logout(@Res({ passthrough: true }) res: Response) {
    res.clearCookie('token');
    res.send('Successfully logged out');
  }

  // After signup the system will send an email with a verification link to the user's email address.
  // The user needs to click on the link to go to a page where they click a button to verify it,that is when this route is called.
  @Post('verify-email')
  @ApiOperation({
    summary: 'Verify user email using token',
    description:
      'This endpoint should be called when the user clicks the verification button which is after clicking the link in their email.<br> So this endpoint should be called from the `/verify-email` route in the frontend, remember to pass the token as a query parameter (so the link will be `/verify-email?token=`).',
  })
  @ApiQuery({
    name: 'token',
    required: true,
    description: 'JWT token from email link',
  })
  @ApiResponse({
    status: 200,
    description: 'Email verified successfully',
    schema: { example: { message: 'Email verified successfully' } },
  })
  @ApiBadRequestResponse({
    description: 'Invalid or expired token, or already verified',
    content: {
      'application/json': {
        examples: {
          userNotFound: {
            summary: 'The user not found or already verified',
            value: {
              statusCode: 400,
              message: 'User not found or already verified',
              error: 'Bad Request',
            },
          },
          invalidCredentials: {
            summary: 'Invalid or expired token',
            value: {
              statusCode: 400,
              message: 'Invalid or expired verification token',
              error: 'Bad Request',
            },
          },
        },
      },
    },
  })
  async verifyEmail(@Query('token') token: string) {
    return await this.authService.verifyEmail(token);
  }

  // In case the user missed the mail or the token expired, the frontend can call this route to resend the verification email.
  @Post('resend-verification-email')
  @ApiOperation({
    summary: 'Resend verification email to user',
    description:
      'This endpoint allows users to request a new verification email if they missed the original one or if the token expired. <br>If the you received "Invalid or expired verification token" error you should call this endpoint to resend the email. ',
  })
  @ApiBody({
    description: 'Email to resend verification to',
    type: ParseEmailPipe,
    schema: { example: { email: 'example@email.com' } },
    required: true,
  })
  @ApiResponse({
    status: 200,
    description: 'Verification email resent successfully',
    schema: {
      example: { message: 'Verification email resent successfully' },
    },
  })
  @ApiNotFoundResponse({
    description: 'User not found',
    schema: {
      example: {
        statusCode: 404,
        message: 'User not found',
        error: 'Not Found',
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Email already verified',
    schema: {
      example: {
        statusCode: 400,
        message: 'Email already verified',
        error: 'Bad Request',
      },
    },
  })
  async resendVerificationEmail(@Body(ParseEmailPipe) email: string) {
    return await this.authService.resendVerificationEmail(email);
  }

  @Post('request-password-reset')
  @ApiOperation({
    summary: 'Request password reset link',
    description: `This endpoint sends a password reset link to the user's email address.<br><br>
    It is used in two cases:<br>
    - If the user clicks the "Forgot Password?" button.<br>
    - If the user previously requested a reset link but the 5-minute token has expired.<br><br>
    Note: The token will only be sent if the email exists and is verified. For security reasons, we always return the same success message, regardless of whether the user exists or is verified.`,
  })
  @ApiBody({
    description:
      'The email address of the user who wants to reset their password.',
    type: ParseEmailPipe,
    schema: { example: { email: 'user@example.com' } },
    required: true,
  })
  @ApiResponse({
    status: 201,
    description: 'Reset password email sent successfully.',
    schema: {
      example: { message: 'Password reset email sent successfully' },
    },
  })
  @ApiResponse({
    status: 500,
    description: 'Failed to send reset password email',
    schema: {
      example: {
        statusCode: 500,
        message: 'Failed to send reset password email',
      },
    },
  })
  async requestPasswordReset(@Body(ParseEmailPipe) email: string) {
    return await this.authService.requestPasswordReset(email);
  }

  @Post('reset-password')
  @ApiOperation({
    summary: 'Reset user password using token',
    description: `This endpoint is used after the user clicks the password reset link from their email.<br><br>
    It should be triggered from the frontend's \`/reset-password\` route.<br>
    The token should be passed as a query parameter in the URL.<br><br>
    The body must include a new password that is between 8 and 28 characters long.`,
  })
  @ApiQuery({
    name: 'token',
    required: true,
    description:
      'The JWT token sent in the reset password email. This must be passed as a query parameter.',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  @ApiBody({
    type: ResetPasswordDto,
    description: 'The new password to set for the user account.',
  })
  @ApiResponse({
    status: 200,
    description: 'Password reset successfully.',
    schema: {
      example: { message: 'Password reset successfully' },
    },
  })
  @ApiResponse({
    status: 400,
    description:
      'Invalid or expired token, or validation error in request body.',
    schema: {
      example: {
        statusCode: 400,
        message: 'Invalid or expired reset password token',
      },
    },
  })
  @ApiResponse({
    status: 404,
    description: 'User not found (after token is verified).',
    schema: {
      example: { statusCode: 404, message: 'User not found' },
    },
  })
  async resetPassword(
    @Query('token') token: string,
    @Body() dto: ResetPasswordDto,
  ) {
    return await this.authService.resetPassword(token, dto);
  }

  @Patch('switch-role')
  @ApiOperation({ summary: 'Switch user role (BUYER ⇌ SUPPLIER)' })
  @ApiOkResponse({
    description: 'Token regenerated with updated role',
    schema: {
      example: {
        message: 'Role switched successfully',
        newRole: 'SUPPLIER',
      },
    },
  })
  @ApiInternalServerErrorResponse({
    description: 'Unexpected role: GUEST should never reach this endpoint',
    schema: {
      example: {
        statusCode: 500,
        message: 'Unexpected role: GUEST should never reach this endpoint',
        error: 'Internal Server Error',
      },
    },
  })
  @ApiJwtAuthGuard()
  @UseGuards(JwtAuthGuard)
  async switchUserRole(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    return await this.authService.switchUserRole(req, res);
  }
}
