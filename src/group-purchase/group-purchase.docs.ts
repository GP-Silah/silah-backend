import { applyDecorators } from '@nestjs/common';
import {
    ApiOperation,
    ApiOkResponse,
    ApiCreatedResponse,
    ApiNotFoundResponse,
    ApiBadRequestResponse,
    ApiForbiddenResponse,
    ApiConflictResponse,
    ApiParam,
    ApiQuery,
} from '@nestjs/swagger';
import { GroupPurchaseResponseDto } from './dtos/groupPurchaseResponse.dto';

/**
 * @description Get all group purchases for a specific product (public).
 */
export function ApiDocsGetAllGroupPurchaseForProduct() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get all group purchases for a product',
            description: `
Retrieves all group purchases related to a specific product.
Includes product, supplier, and joined buyers information.`,
        }),
        ApiParam({
            name: 'id',
            description: 'Product unique identifier',
            example: 'prd_12345',
        }),
        ApiOkResponse({
            description: 'Group purchases successfully retrieved.',
            type: [GroupPurchaseResponseDto],
        }),
        ApiNotFoundResponse({
            description: 'Product not found.',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Product with ID prd_12345 not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}

/**
 * @description Get a single group purchase by its ID (public).
 */
export function ApiDocsGetGroupById() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get group purchase by ID',
            description: `Retrieve a group purchase along with its product, supplier, and joined buyers.`,
        }),
        ApiParam({
            name: 'id',
            description: 'Group purchase unique identifier',
            example: 'gp_12345',
        }),
        ApiOkResponse({
            description: 'Group purchase successfully retrieved.',
            type: GroupPurchaseResponseDto,
        }),
        ApiNotFoundResponse({
            description: 'Group purchase not found.',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Group Purchase with ID gp_12345 not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}

/**
 * @description Get suitable group purchases for a product for the authenticated buyer.
 */
export function ApiDocsGetSuitableGroupPurchasesForProduct() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get suitable group purchases for product (Buyer only)',
            description: `
Fetches open group purchases for a specific product in the buyer's city.
Only returns groups that still have available quantity.`,
        }),
        ApiParam({
            name: 'id',
            description: 'Product unique identifier',
            example: 'prd_12345',
        }),
        ApiOkResponse({
            description: 'Suitable group purchases retrieved successfully.',
            type: [GroupPurchaseResponseDto],
        }),
        ApiNotFoundResponse({
            description: 'Product or buyer not found.',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Product with ID prd_12345 or buyer not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}

/**
 * @description Start a new group purchase for a product (buyer-only).
 */
export function ApiDocsStartGroupPurchase() {
    return applyDecorators(
        ApiOperation({
            summary: 'Start a new group purchase (Buyer only)',
            description: `
Allows a buyer to start a new group purchase for a product.
Automatically creates pre-invoice for the buyer.`,
        }),
        ApiParam({
            name: 'id',
            description: 'Product unique identifier',
            example: 'prd_12345',
        }),
        ApiQuery({
            name: 'quantity',
            description: 'Number of units to start the group purchase with',
            example: 10,
        }),
        ApiCreatedResponse({
            description: 'Group purchase successfully created.',
            type: GroupPurchaseResponseDto,
        }),
        ApiBadRequestResponse({
            description: 'Invalid quantity or group purchase not allowed.',
            schema: {
                example: {
                    statusCode: 400,
                    message:
                        'Quantity must exist and be greater than zero, found: 0',
                    error: 'Bad Request',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'Buyer or product not found.',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Buyer or product not found',
                    error: 'Not Found',
                },
            },
        }),
        ApiConflictResponse({
            description: 'Open group purchase already exists.',
            schema: {
                example: {
                    statusCode: 409,
                    message:
                        'There is already an open group purchase for this product',
                    error: 'Conflict',
                },
            },
        }),
    );
}

/**
 * @description Join an existing group purchase (buyer-only).
 */
export function ApiDocsJoinGroupPurchase() {
    return applyDecorators(
        ApiOperation({
            summary: 'Join an existing group purchase (Buyer only)',
            description: `
Allows a buyer to join an open group purchase.
Automatically updates totals and creates pre-invoice for the buyer.`,
        }),
        ApiParam({
            name: 'id',
            description: 'Group purchase unique identifier',
            example: 'gp_12345',
        }),
        ApiQuery({
            name: 'quantity',
            description: 'Number of units to join with',
            example: 5,
        }),
        ApiOkResponse({
            description: 'Successfully joined the group purchase.',
            type: GroupPurchaseResponseDto,
        }),
        ApiBadRequestResponse({
            description:
                'Invalid quantity or group purchase not open/expired/city mismatch.',
            schema: {
                example: {
                    statusCode: 400,
                    message: 'This group purchase has expired',
                    error: 'Bad Request',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'Buyer or group purchase not found.',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Buyer or group purchase not found',
                    error: 'Not Found',
                },
            },
        }),
        ApiConflictResponse({
            description: 'Buyer already joined this group purchase.',
            schema: {
                example: {
                    statusCode: 409,
                    message: 'You already joined this group purchase',
                    error: 'Conflict',
                },
            },
        }),
    );
}
