import { applyDecorators } from '@nestjs/common';
import {
    ApiCookieAuth,
    ApiUnauthorizedResponse,
    ApiSecurity,
} from '@nestjs/swagger';

export function ApiDocsJwtAuthGuard() {
    return applyDecorators(
        ApiSecurity('cookie'), // indicates cookie-based auth in Swagger
        ApiCookieAuth('token'), // cookie name is "token"
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
        // Optional: extra note for frontend devs
        // This is purely documentation; it won’t affect Swagger UI behavior
        ApiSecurity('bearer', []), // if you ever also support Authorization header
    );
}
