import { applyDecorators } from '@nestjs/common';
import {
    ApiOperation,
    ApiResponse,
    ApiBearerAuth,
    ApiBadRequestResponse,
    ApiNotFoundResponse,
    ApiForbiddenResponse,
    ApiBody,
    ApiQuery,
    ApiHeader,
} from '@nestjs/swagger';
import {
    ReviewResponseDto,
    SupplierReviewResponseDto,
    ItemReviewResponseDto,
} from './dtos/reviewResponse.dto';
import { CreateReviewDto } from './dtos/createReview.dto';

export function ApiDocsGetSupplierReviews() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get all reviews for a supplier',
            description: `Fetches all reviews written for a supplier. Does not include item reviews.
                Reviews are ordered by creation date (latest first).`,
        }),
        ApiQuery({
            name: 'lang',
            required: false,
            enum: ['ar', 'en'],
            description:
                'Force response language. Defaults to user preference or English.',
            example: 'ar',
        }),
        ApiHeader({
            name: 'accept-language',
            description:
                'Optional header to specify response translation language (e.g., `ar`, `en`). Used if `lang` query param not provided.',
            required: false,
            example: 'ar',
        }),
        ApiResponse({
            status: 200,
            description: 'List of reviews for the supplier',
            type: [SupplierReviewResponseDto],
        }),
        ApiNotFoundResponse({
            description: 'Supplier not found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'No supplier found with ID: 123',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsGetReviewById() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get a single review by its ID',
            description:
                'Includes buyer, supplier, and item reviews if available.',
        }),
        ApiResponse({
            status: 200,
            description: 'Review details',
            type: ReviewResponseDto,
        }),
        ApiNotFoundResponse({
            description: 'Review not found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'No review found with ID: 123',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsGetItemReviews() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get reviews for a specific item (product or service)',
            description:
                'Fetches all reviews for a given product or service item ID, ordered by creation date (latest first).',
        }),
        ApiQuery({
            name: 'lang',
            required: false,
            enum: ['ar', 'en'],
            description:
                'Force response language. Defaults to user preference or English.',
            example: 'ar',
        }),
        ApiHeader({
            name: 'accept-language',
            description:
                'Optional header to specify response translation language (e.g., `ar`, `en`). Used if `lang` query param not provided.',
            required: false,
            example: 'ar',
        }),
        ApiResponse({
            status: 200,
            description: 'List of item reviews',
            type: [ItemReviewResponseDto],
        }),
        ApiNotFoundResponse({
            description: 'Item not found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'No product or service found with ID: 123',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsCreateReview() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Create a review for an order or invoice',
            description: `Buyer can create a review for a completed order or fully paid invoice.
                Supports both supplier rating and item reviews.
                Multiple item reviews can be included in the request.
                Only the buyer who made the order/invoice can write the review.`,
        }),
        ApiBody({
            description: 'Request body for creating a review',
            type: CreateReviewDto,
        }),
        ApiResponse({
            status: 201,
            description: 'Review created successfully',
            type: ReviewResponseDto,
        }),
        ApiBadRequestResponse({
            description: 'Validation failed',
            schema: {
                oneOf: [
                    {
                        example: {
                            statusCode: 400,
                            message: 'You already reviewd order with ID: 123',
                            error: 'Bad Request',
                        },
                    },
                    {
                        example: {
                            statusCode: 400,
                            message:
                                'Order must be marked as completed before writting a review',
                            error: 'Bad Request',
                        },
                    },
                    {
                        example: {
                            statusCode: 400,
                            message:
                                'orderItemId is required for order-based reviews',
                            error: 'Bad Request',
                        },
                    },
                    {
                        example: {
                            statusCode: 400,
                            message:
                                'invoiceItemId is required for invoice-based reviews',
                            error: 'Bad Request',
                        },
                    },
                    {
                        example: {
                            statusCode: 400,
                            message:
                                'Cannot write a review for this invoice because it was created by upgrading a pre-invoice. Reviews are only allowed for invoices tied to actual products or services.',
                            error: 'Bad Request',
                        },
                    },
                ],
            },
        }),
        ApiForbiddenResponse({
            description: 'User is not allowed to review this order/invoice',
            schema: {
                example: {
                    statusCode: 403,
                    message:
                        "You can't write a review to an order or an invoice you haven't made",
                    error: 'Forbidden',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'Order, invoice, buyer, or supplier not found',
            schema: {
                oneOf: [
                    {
                        example: {
                            statusCode: 404,
                            message: 'No order or invoice found with ID: 123',
                            error: 'Not Found',
                        },
                    },
                    {
                        example: {
                            statusCode: 404,
                            message: 'Buyer or Supplier not found',
                            error: 'Not Found',
                        },
                    },
                ],
            },
        }),
    );
}
