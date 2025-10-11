import { applyDecorators } from '@nestjs/common';
import { ApiResponse } from '@nestjs/swagger';

export function ApiDocsVerifiedGuard() {
    return applyDecorators(
        ApiResponse({
            status: 423, // Workaround for Swagger UI
            description:
                'Email not verified. <br>Note: The actual response returned by the API is 403 Forbidden, but Swagger UI does not allow multiple identical status codes for different errors, so 423 Locked is used here as a workaround for documentation purposes.',
            schema: {
                example: {
                    statusCode: 403,
                    message: 'User email is not verified',
                    error: 'Forbidden',
                },
            },
        }),
    );
}
