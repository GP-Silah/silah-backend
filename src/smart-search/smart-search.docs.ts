import { applyDecorators } from '@nestjs/common';
import {
    ApiOperation,
    ApiResponse,
    ApiBadRequestResponse,
    ApiBadGatewayResponse,
    ApiBody,
} from '@nestjs/swagger';
import { SmartSearchRequestDto } from './dtos/smartSearchRequest.dto';
import { SmartSearchResponseDto } from './dtos/smartSearchResponse.dto';

export function ApiDocsSmartSearch() {
    return applyDecorators(
        ApiOperation({
            summary: 'Find similar items (Products or Services)',
            description: `Performs a smart similarity search between items (products or services) using AI embeddings.<br>
            You can either:
            <ul>
                <li>Provide an existing <strong>itemId</strong> to find similar alternatives.</li>
                <li>Or provide free-text <strong>text</strong> to perform a semantic search across all products and services.</li>
            </ul>
            The backend automatically determines whether the provided item belongs to products or services.<br><br>
            The AI service (FastAPI backend) computes similarity scores using embeddings and returns the most relevant matches.<br><br>
            <strong>Behavior:</strong>
            <ul>
                <li>If <code>itemId</code> is provided → search is limited to the same type (products or services).</li>
                <li>If <code>text</code> is provided → searches both products and services simultaneously.</li>
                <li>If both are missing → request will fail with a <code>400 Bad Request</code>.</li>
            </ul>
            <strong>Note:</strong> This endpoint depends on the <code>AI_BACKEND_URL</code> environment variable and will throw a <code>502 Bad Gateway</code> if the AI service is offline.`,
        }),
        ApiBody({
            type: SmartSearchRequestDto,
            description:
                'Provide either an itemId or a text. If itemId is provided, it will automatically detect the item type (product or service).',
            examples: {
                byItemId: {
                    summary: 'Search by existing item ID',
                    description:
                        'Finds items similar to the given product or service ID.',
                    value: { itemId: 'a1b2c3d4e5', text: undefined },
                },
                byText: {
                    summary: 'Search by free text',
                    description:
                        'Performs AI-based semantic search for items similar to the provided text.',
                    value: { text: 'Handmade wooden spoon' },
                },
            },
        }),
        ApiResponse({
            status: 200,
            description:
                'List of similar items (products or services) ranked by similarity.',
            type: [SmartSearchResponseDto],
        }),
        ApiBadRequestResponse({
            description: 'Invalid or missing parameters.',
            schema: {
                oneOf: [
                    {
                        example: {
                            statusCode: 400,
                            message: 'Either itemId or text must be provided',
                            error: 'Bad Request',
                        },
                    },
                    {
                        example: {
                            statusCode: 400,
                            message: 'No item found with the given ID',
                            error: 'Bad Request',
                        },
                    },
                    {
                        example: {
                            statusCode: 400,
                            message:
                                'Embedding not found for item a1b2c3d4e5 (PRODUCT)',
                            error: 'Bad Request',
                        },
                    },
                ],
            },
        }),
        ApiBadGatewayResponse({
            description:
                'AI backend (FastAPI) is unavailable or returned invalid data.',
            schema: {
                oneOf: [
                    {
                        example: {
                            statusCode: 502,
                            message: 'AI backend is unavailable',
                            error: 'Bad Gateway',
                        },
                    },
                    {
                        example: {
                            statusCode: 502,
                            message: 'Invalid AI response format',
                            error: 'Bad Gateway',
                        },
                    },
                    {
                        example: {
                            statusCode: 502,
                            message: 'Failed to generate embedding for item',
                            error: 'Bad Gateway',
                        },
                    },
                ],
            },
        }),
    );
}
