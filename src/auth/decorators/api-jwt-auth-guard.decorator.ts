import { applyDecorators } from '@nestjs/common';
import {
  ApiCookieAuth,
  ApiUnauthorizedResponse,
  ApiForbiddenResponse,
  ApiHeader,
} from '@nestjs/swagger';

export function ApiJwtAuthGuard() {
  return applyDecorators(
    ApiCookieAuth('token'),
    ApiHeader({
      name: 'Cookie',
      description:
        'JWT token must be set in the cookie named "token". Example: token=your_jwt_token_here',
      required: true,
    }),
    ApiUnauthorizedResponse({
      description: 'Unauthorized: Token missing or invalid/expired.',
      schema: {
        oneOf: [
          {
            example: {
              statusCode: 401,
              message: 'No token found in cookies',
              error: 'Unauthorized',
            },
          },
          {
            example: {
              statusCode: 401,
              message: 'Invalid or expired token',
              error: 'Unauthorized',
            },
          },
        ],
      },
    }),
  );
}
