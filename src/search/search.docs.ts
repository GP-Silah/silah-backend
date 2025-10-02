import { applyDecorators } from '@nestjs/common';
import {
    ApiNotFoundResponse,
    ApiOkResponse,
    ApiOperation,
    ApiQuery,
} from '@nestjs/swagger';
import { UserResponseDTO } from 'src/user/dtos/userResponse.dto';

export function ApiDocsGetSearchUsers() {
    return applyDecorators(
        ApiOperation({
            summary: 'Search users by name',
            description:
                'Returns a list of users that match the provided name.',
        }),
        ApiQuery({
            name: 'name',
            type: String,
            description: 'Name (or partial name) to search users by',
            example: 'Sarah',
            required: false,
        }),
        ApiOkResponse({
            description: 'Users found',
            type: [UserResponseDTO],
        }),
        ApiNotFoundResponse({
            description: 'No users found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'No users found with the name',
                    error: 'Not Found',
                },
            },
        }),
    );
}
