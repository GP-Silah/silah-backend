import { Body, Controller, Post, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Response } from 'express';
import { SignupDto } from './dtos/signup.dto';
import {
  ApiTags,
  ApiResponse,
  ApiBody,
  ApiBadRequestResponse,
  ApiOperation,
} from '@nestjs/swagger';
import { LoginDto } from './dtos/login.dto';

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

  // after signup the system will send an email with a verification link to the user's email address. The user needs to click on the link to go to a page where they click a button to verify it, that is when this route is called.
  @Post('verify-email')
  async verifyEmail() {}

  @Post('request-password-reset')
  async requestPasswordReset() {}

  @Post('reset-password')
  async resetPassword() {}
}
