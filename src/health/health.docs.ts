import { applyDecorators } from '@nestjs/common';
import { ApiOperation, ApiResponse } from '@nestjs/swagger';

export function ApiDocsHealthCheck() {
    return applyDecorators(
        ApiOperation({ summary: 'Check API health status' }),
        ApiResponse({
            status: 200,
            description: 'API is healthy',
            schema: {
                example: {
                    status: 'ok',
                    info: {
                        database: { status: 'up' },
                    },
                    error: {},
                    details: {
                        database: { status: 'up' },
                    },
                },
            },
        }),
    );
}
