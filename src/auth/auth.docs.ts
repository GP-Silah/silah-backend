import { applyDecorators } from '@nestjs/common';
import {
    ApiBadRequestResponse,
    ApiBody,
    ApiInternalServerErrorResponse,
    ApiNotFoundResponse,
    ApiOkResponse,
    ApiOperation,
    ApiQuery,
    ApiResponse,
} from '@nestjs/swagger';
import { SignupDto } from './dtos/signup.dto';
import { LoginDto } from './dtos/login.dto';
import { ResetPasswordDto } from './dtos/resetPassword.dto';

export function ApiDocsSignUp() {
    return applyDecorators(
        ApiOperation({
            summary: 'Registers a new user and returns a JWT token in a cookie',
        }),
        ApiBody({ type: SignupDto }),
        ApiResponse({
            status: 201,
            description: 'User signed up successfully. JWT sent in cookie.',
            schema: {
                example: {
                    message: 'Signup successful',
                },
            },
        }),
        ApiBadRequestResponse({
            description: 'Bad Request - validation or conflict',
            content: {
                'application/json': {
                    schema: {
                        oneOf: [
                            // Optional: if you want typed schema matching different error shapes
                            {
                                example: {
                                    statusCode: 400,
                                    message:
                                        'These categories are invalid: Cleaning, Laundry',
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
                                message:
                                    'These categories are invalid: Cleaning, Laundry',
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
        }),
    );
}

export function ApiDocsLogin() {
    return applyDecorators(
        ApiOperation({
            summary: 'Login user and send back JWT token as a cookie',
            description:
                'Either "email" or "crn" must be provided, but not both.',
        }),
        ApiBody({
            schema: {
                oneOf: [
                    {
                        type: 'object',
                        required: ['email', 'password'],
                        properties: {
                            email: { type: 'string', format: 'email' },
                            password: { type: 'string' },
                        },
                    },
                    {
                        type: 'object',
                        required: ['crn', 'password'],
                        properties: {
                            crn: { type: 'string' },
                            password: { type: 'string' },
                        },
                    },
                ],
            },
            examples: {
                loginWithEmail: {
                    summary: 'Login using email and password',
                    value: {
                        email: 'user@example.com',
                        password: 'securePassword123',
                    },
                },
                loginWithCrn: {
                    summary: 'Login using CRN and password',
                    value: {
                        crn: '1234567890',
                        password: 'securePassword123',
                    },
                },
            },
        }),
        ApiResponse({
            status: 201,
            description: 'User successfully logged in',
            schema: {
                example: {
                    message: 'Login successful',
                },
            },
        }),
        ApiResponse({
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
                            summary:
                                'The email or CRN exists, but the password is incorrect',
                            value: {
                                statusCode: 400,
                                message: 'Invalid credentials',
                                error: 'Bad Request',
                            },
                        },
                    },
                },
            },
        }),
    );
}

export function ApiDocsLogout() {
    return applyDecorators(
        ApiOperation({ summary: 'Logout user by clearing token cookie' }),
        ApiResponse({
            status: 200,
            description: 'Successfully logged out',
            schema: { example: 'Successfully logged out' },
        }),
    );
}

export function ApiDocsVerifyEmail() {
    return applyDecorators(
        ApiOperation({
            summary: 'Verify user email using token',
            description:
                'This endpoint should be called when the user clicks the verification button which is after clicking the link in their email.<br> So this endpoint should be called from the `/verify-email` route in the frontend, remember to pass the token as a query parameter (so the link will be `/verify-email?token=`).',
        }),
        ApiQuery({
            name: 'token',
            required: true,
            description: 'JWT token from email link',
        }),
        ApiResponse({
            status: 200,
            description: 'Email verified successfully',
            schema: { example: { message: 'Email verified successfully' } },
        }),
        ApiBadRequestResponse({
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
                                message:
                                    'Invalid or expired verification token',
                                error: 'Bad Request',
                            },
                        },
                    },
                },
            },
        }),
    );
}

export function ApiDocsResendVerificationEmail() {
    return applyDecorators(
        ApiOperation({
            summary: 'Resend verification email to user',
            description:
                'This endpoint allows users to request a new verification email if they missed the original one or if the token expired. <br>If the you received "Invalid or expired verification token" error you should call this endpoint to resend the email. ',
        }),
        ApiBody({
            description: 'Email to resend verification to',
            schema: { example: { email: 'example@email.com' } },
            required: true,
        }),
        ApiResponse({
            status: 200,
            description: 'Verification email resent successfully',
            schema: {
                example: { message: 'Verification email resent successfully' },
            },
        }),
        ApiNotFoundResponse({
            description: 'User not found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'User not found',
                    error: 'Not Found',
                },
            },
        }),
        ApiBadRequestResponse({
            description: 'Email already verified',
            schema: {
                example: {
                    statusCode: 400,
                    message: 'Email already verified',
                    error: 'Bad Request',
                },
            },
        }),
    );
}

export function ApiDocsRequestPasswordReset() {
    return applyDecorators(
        ApiOperation({
            summary: 'Request password reset link',
            description: `This endpoint sends a password reset link to the user's email address.<br><br>
            It is used in two cases:<br>
            - If the user clicks the "Forgot Password?" button.<br>
            - If the user previously requested a reset link but the 5-minute token has expired.<br><br>
            Note: The token will only be sent if the email exists and is verified. For security reasons, we always return the same success message, regardless of whether the user exists or is verified.`,
        }),
        ApiBody({
            description:
                'The email address of the user who wants to reset their password.',
            schema: { example: { email: 'user@example.com' } },
            required: true,
        }),
        ApiResponse({
            status: 201,
            description: 'Reset password email sent successfully.',
            schema: {
                example: { message: 'Password reset email sent successfully' },
            },
        }),
        ApiResponse({
            status: 500,
            description: 'Failed to send reset password email',
            schema: {
                example: {
                    statusCode: 500,
                    message: 'Failed to send reset password email',
                },
            },
        }),
    );
}

export function ApiDocsResetPassword() {
    return applyDecorators(
        ApiOperation({
            summary: 'Reset user password using token',
            description: `This endpoint is used after the user clicks the password reset link from their email.<br><br>
    It should be triggered from the frontend's \`/reset-password\` route.<br>
    The token should be passed as a query parameter in the URL.<br><br>
    The body must include a new password that is between 8 and 28 characters long.`,
        }),
        ApiQuery({
            name: 'token',
            required: true,
            description:
                'The JWT token sent in the reset password email. This must be passed as a query parameter.',
            example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        }),
        ApiBody({
            type: ResetPasswordDto,
            description: 'The new password to set for the user account.',
        }),
        ApiResponse({
            status: 200,
            description: 'Password reset successfully.',
            schema: {
                example: { message: 'Password reset successfully' },
            },
        }),
        ApiResponse({
            status: 400,
            description:
                'Invalid or expired token, or validation error in request body.',
            schema: {
                example: {
                    statusCode: 400,
                    message: 'Invalid or expired reset password token',
                },
            },
        }),
        ApiResponse({
            status: 404,
            description: 'User not found (after token is verified).',
            schema: {
                example: { statusCode: 404, message: 'User not found' },
            },
        }),
    );
}

export function ApiDocsSwitchRole() {
    return applyDecorators(
        ApiOperation({ summary: 'Switch user role (BUYER ⇌ SUPPLIER)' }),
        ApiOkResponse({
            description: 'Token regenerated with updated role',
            schema: {
                example: {
                    message: 'Role switched successfully',
                    newRole: 'SUPPLIER',
                },
            },
        }),
        ApiInternalServerErrorResponse({
            description:
                'Unexpected role: GUEST should never reach this endpoint',
            schema: {
                example: {
                    statusCode: 500,
                    message:
                        'Unexpected role: GUEST should never reach this endpoint',
                    error: 'Internal Server Error',
                },
            },
        }),
    );
}
