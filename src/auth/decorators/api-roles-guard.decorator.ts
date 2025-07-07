import { applyDecorators } from '@nestjs/common';
import { ApiForbiddenResponse } from '@nestjs/swagger';

export function ApiRolesGuard() {
    return applyDecorators(
        ApiForbiddenResponse({
            description:
                'Forbidden: You do not have access to this resource (role mismatch).',
            schema: {
                example: {
                    statusCode: 403,
                    message: 'You do not have access to this resource',
                    error: 'Forbidden',
                },
            },
        }),
    );
}
