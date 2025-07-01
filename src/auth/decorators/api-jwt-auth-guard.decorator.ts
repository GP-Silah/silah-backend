import { applyDecorators } from '@nestjs/common';
import {
  ApiCookieAuth,
  ApiUnauthorizedResponse,
  ApiForbiddenResponse,
} from '@nestjs/swagger';

export function ApiJwtAuthGuard() {
  return applyDecorators(
    ApiCookieAuth(),
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
