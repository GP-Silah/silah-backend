import { applyDecorators } from '@nestjs/common';
import {
    ApiBadRequestResponse,
    ApiBearerAuth,
    ApiBody,
    ApiConsumes,
    ApiNotFoundResponse,
    ApiOkResponse,
    ApiOperation,
    ApiParam,
    ApiQuery,
    ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { UserResponseDTO } from './dtos/userResponse.dto';
import { UpdateUserDto } from './dtos/updateUser.dto';

export function ApiDocsGetUserByEmail() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get user by email',
            description: 'Fetches a single user using their email address.',
        }),
        ApiParam({
            name: 'email',
            type: String,
            description: 'Email address of the user',
            example: 'example@email.com',
        }),
        ApiOkResponse({
            description: 'User found',
            type: UserResponseDTO,
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
    );
}

export function ApiDocsGetUserByCrn() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get user by their CRN',
            description: 'Fetches a user using their unique CRN.',
        }),
        ApiParam({
            name: 'crn',
            type: String,
            description: 'Customer Registration Number of the user',
            example: '0123456789',
        }),
        ApiOkResponse({
            description: 'User found',
            type: UserResponseDTO,
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
    );
}
export function ApiDocsGetUserByName() {
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
            required: true,
        }),
        ApiOkResponse({
            description: 'Users found',
            type: [UserResponseDTO],
        }),
        ApiBadRequestResponse({
            description: 'Invalid input data',
            schema: {
                example: {
                    statusCode: 400,
                    message: 'Name parameter is required',
                    error: 'Bad Request',
                },
            },
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

export function ApiDocsGetCurrentUserData() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get current user',
            description: "Returns the currently authenticated user's data.",
        }),
        ApiBearerAuth(),
        ApiOkResponse({
            description: 'Current user data retrieved successfully',
            type: UserResponseDTO,
        }),
    );
}

export function ApiDocsUpdateCurrentUserData() {
    return applyDecorators(
        ApiOperation({
            summary: 'Update current user',
            description:
                "Updates the currently authenticated user's profile information.",
        }),
        ApiBearerAuth(),
        ApiBody({
            description:
                "User data to update (you don't have to not send all fields, only the ones you want to change will be updated).",
            type: UpdateUserDto,
            required: false,
        }),
        ApiOkResponse({
            description: 'User updated successfully',
            type: UserResponseDTO,
        }),
        ApiBadRequestResponse({
            description: 'Invalid input data',
            schema: {
                example: {
                    statusCode: 400,
                    message: 'These categories are invalid: Hi, LOL',
                    error: 'Bad Request',
                },
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
    );
}

export function ApiDocsGetUserProfilePicture() {
    return applyDecorators(
        ApiOperation({
            summary: "Get user's profile picture URL",
            description:
                "Retrieves the URL of a user's profile picture that is stored on R2. " +
                'Throws a 404 error if the user or their profile picture does not exist.',
        }),
        ApiParam({
            name: 'id',
            type: String,
            description:
                'ID of the user whose profile picture URL is being retrieved',
            example: 'b4f2d8c1-9876-5432-10ba-2f3e4d5c6789',
        }),
        ApiOkResponse({
            description: 'Profile picture URL retrieved successfully',
            schema: {
                example: {
                    pfpUrl: 'https://cdn.example.com/pfp/USER_ID.jpeg?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20250101T000000Z&X-Amz-Expires=3600&X-Amz-Signature=REDACTED',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'User or profile picture not found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Profile picture not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsGetUsersProfilePicturesUrls() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get profile pictures for multiple users',
            description:
                'Retrieves the profile picture URLs for multiple users by their IDs. Only valid UUIDs are considered.',
        }),
        ApiBody({
            description:
                'Array of user IDs to retrieve profile picture URLs for',
            schema: {
                type: 'object',
                properties: {
                    ids: {
                        type: 'array',
                        items: { type: 'string', format: 'uuid' },
                        example: [
                            'a3e1c9f0-1234-5678-90ab-1c2d3e4f5678',
                            'b4f2d8c1-9876-5432-10ba-2f3e4d5c6789',
                        ],
                    },
                },
                required: ['ids'],
            },
        }),
        ApiOkResponse({
            description: 'Profile picture URLs retrieved successfully',
            schema: {
                example: [
                    {
                        id: 'a3e1c9f0-1234-5678-90ab-1c2d3e4f5678',
                        pfpUrl: 'https://cdn.example.com/pfp/USER_ID.jpeg?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20250101T000000Z&X-Amz-Expires=3600&X-Amz-Signature=REDACTED',
                    },
                    {
                        id: 'b4f2d8c1-9876-5432-10ba-2f3e4d5c6789',
                        pfpUrl: null,
                    },
                ],
            },
        }),
        ApiBadRequestResponse({
            description: 'Request body must contain an "ids" array',
            schema: {
                example: {
                    statusCode: 400,
                    message: 'Request body must contain an "ids" array',
                    error: 'Bad Request',
                },
            },
        }),
        ApiBadRequestResponse({
            description: 'Invalid input data',
            schema: {
                example: {
                    statusCode: 400,
                    message: 'No user IDs provided',
                    error: 'Bad Request',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'No users found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'No users found with the provided IDs',
                    error: 'Not Found',
                },
            },
        }),
    );
}
export function ApiDocsUploadProfilePicture() {
    return applyDecorators(
        ApiBearerAuth(), // JWT authentication
        ApiOperation({
            summary: 'Update user profile picture',
            description:
                'Uploads a new profile picture for the authenticated user and updates their record. Replaces the previous picture if it exists.<br>' +
                '<strong>Note:</strong> The file must be an image (PNG, JPEG, WebP) and cannot exceed 5MB in size.<br>' +
                "<strong>IMPORTANT:</strong> Please ensure that uploaded images comply with Islamic laws. This means avoiding haram content such as music-related images, depictions of women's bodies (even hands), or any illustrations of living beings (humans, animals, etc.) whether drawn or digital.",
        }),
        ApiConsumes('multipart/form-data'),
        ApiBody({
            description: 'Profile picture file to upload',
            schema: {
                type: 'object',
                properties: {
                    file: {
                        type: 'string',
                        format: 'binary',
                    },
                },
            },
        }),
        ApiOkResponse({
            description: 'Profile picture updated successfully',
            schema: {
                example: {
                    message: 'Profile picture updated successfully',
                    pfpFileName: 'user-avatar/12345.png',
                },
            },
        }),
        ApiBadRequestResponse({
            description: 'Bad request. File missing or invalid format.',
            schema: {
                example: {
                    statusCode: 400,
                    message: 'No file provided or invalid file type',
                    error: 'Bad Request',
                },
            },
        }),
        ApiUnauthorizedResponse({
            description: 'Unauthorized. JWT token missing or invalid.',
            schema: {
                example: {
                    statusCode: 401,
                    message: 'Unauthorized',
                    error: 'Unauthorized',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'User not found or profile picture cannot be updated',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'User not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsDeleteProfilePicture() {
    return applyDecorators(
        ApiBearerAuth(), // JWT authentication
        ApiOperation({
            summary: 'Delete current user profile picture',
            description:
                "Deletes the authenticated user's current profile picture and replaces it with a default avatar.",
        }),
        ApiOkResponse({
            description: 'Profile picture deleted successfully',
            schema: {
                example: {
                    message: 'Profile picture deleted successfully',
                },
            },
        }),
        ApiNotFoundResponse({
            description:
                'User not found or already has the default profile picture',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Profile picture not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}
