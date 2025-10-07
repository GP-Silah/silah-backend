import { applyDecorators } from '@nestjs/common';
import {
    ApiOperation,
    ApiResponse,
    ApiBearerAuth,
    ApiBody,
    ApiConsumes,
    ApiParam,
    ApiQuery,
    ApiNotFoundResponse,
    getSchemaPath,
} from '@nestjs/swagger';
import { SupplierResponseDto } from './dtos/supplierResponse.dto';
import { StoreStatus, SupplierPlan, SupplierStatus } from '@prisma/client';
import { UpdateSupplierDto } from './dtos/updateSupplier.dto';
import { StorefrontResponseDto } from './dtos/storefrontResponse.dto';
import { InactiveSupplierResponseDto } from './dtos/inactiveSupplierResponse.dto';
import { StockLevelsResponseDto } from './dtos/stockLevelsResponse.dto';

export function ApiDocsGetMySupplierData() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Get current supplier profile',
            description:
                'Retrieves the supplier data of the authenticated user. ' +
                'Returns either full supplier data if active, or a minimal inactive DTO if the supplier is inactive.',
        }),
        ApiResponse({
            status: 200,
            description: 'Successfully retrieved supplier profile.',
            schema: {
                oneOf: [
                    { $ref: getSchemaPath(SupplierResponseDto) },
                    { $ref: getSchemaPath(InactiveSupplierResponseDto) },
                ],
            },
        }),
        ApiNotFoundResponse({
            description: 'Supplier not found for the given user.',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Supplier with id 9932-we432 not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsGetMyStoreData() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Get current supplier store data',
            description:
                'Retrieves the storefront information of the authenticated supplier, including store status, bio, banner, and delivery fees. Does not include favorite categories or free trial info.',
        }),
        ApiResponse({
            status: 200,
            description: 'Successfully retrieved supplier store data.',
            schema: {
                oneOf: [
                    { $ref: getSchemaPath(StorefrontResponseDto) },
                    { $ref: getSchemaPath(InactiveSupplierResponseDto) },
                ],
            },
        }),
        ApiNotFoundResponse({
            description: 'Supplier not found for the given user.',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Supplier with id 9932-we432 not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsGetStockLevels() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Get supplier stock levels',
            description:
                'Retrieves the stock levels for all products of the authenticated supplier. ' +
                'Products are grouped into stock levels: VERY_LOW, LOW, AVERAGE, and GOOD. ' +
                'Each group contains a count of products and the list of product details including ID, name, and current stock.',
        }),
        ApiResponse({
            status: 200,
            description: 'Stock levels retrieved successfully.',
            schema: {
                $ref: getSchemaPath(StockLevelsResponseDto),
            },
        }),
        ApiNotFoundResponse({
            description: 'Supplier not found for the given user.',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Supplier not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsUpdateMySupplierData() {
    return applyDecorators(
        ApiOperation({
            summary: 'Update current supplier profile',
            description:
                'Allows the authenticated supplier to update their profile information such as store status, store closed message, store bio, banner filename, and delivery fees. Only supplier-related fields can be updated.',
        }),
        ApiBody({
            type: UpdateSupplierDto,
            description: 'Supplier fields that can be updated.',
        }),
        ApiResponse({
            status: 200,
            description: 'Supplier profile updated successfully.',
            type: SupplierResponseDto,
        }),
        ApiNotFoundResponse({
            description: 'Supplier not found for the given user.',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Supplier with id 9932-we432 not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsGetFavoriteCategories() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Get supplier favorite categories',
            description:
                'Retrieves the list of favorite subcategories for the authenticated supplier. Each item contains the category ID and name.',
        }),
        ApiResponse({
            status: 200,
            description: 'Successfully retrieved favorite categories.',
            schema: {
                type: 'array',
                items: {
                    type: 'object',
                    properties: {
                        id: { type: 'number', example: 16 },
                        name: { type: 'string', example: 'Animal Feed' },
                    },
                },
                example: [
                    { id: 16, name: 'Animal Feed' },
                    { id: 33, name: 'Jewelry & Watches' },
                ],
            },
        }),
        ApiNotFoundResponse({
            description:
                'Supplier not found when fetching favorite categories.',
            schema: {
                example: {
                    statusCode: 404,
                    message:
                        'Supplier not found when fetching favorite categories',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsToggleFavoriteCategory() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Toggle a favorite category for supplier',
            description:
                "Adds a category to the supplier's favorite categories if not already present, or removes it if already present. Returns a message and updated favorite categories list.",
        }),
        ApiBody({
            schema: {
                type: 'object',
                properties: {
                    categoryId: {
                        type: 'number',
                        description:
                            'The ID of the category to toggle in favorites',
                        example: 16,
                    },
                },
                required: ['categoryId'],
            },
        }),
        ApiResponse({
            status: 200,
            description: 'Successfully toggled favorite category.',
            schema: {
                type: 'object',
                properties: {
                    message: {
                        type: 'string',
                        example: 'Category added to favorites.',
                    },
                    favoriteCategories: {
                        type: 'array',
                        items: {
                            type: 'object',
                            properties: {
                                id: { type: 'number', example: 16 },
                                name: {
                                    type: 'string',
                                    example: 'Animal Feed',
                                },
                            },
                        },
                        example: [
                            { id: 16, name: 'Animal Feed' },
                            { id: 33, name: 'Jewelry & Watches' },
                        ],
                    },
                },
            },
        }),
        ApiResponse({
            status: 400,
            description:
                'Invalid category ID provided or category does not exist.',
            schema: {
                oneOf: [
                    {
                        example: {
                            statusCode: 400,
                            message:
                                'Invalid category ID: abc123 (must be a number)',
                            error: 'Bad Request',
                        },
                    },
                    {
                        example: {
                            statusCode: 400,
                            message: 'Category with id 9999 does not exist',
                            error: 'Bad Request',
                        },
                    },
                ],
            },
        }),
        ApiNotFoundResponse({
            description: 'Supplier not found.',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Supplier not found.',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsGetSupplierPlan() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Get current supplier plan',
            description:
                'Retrieves the current subscription plan of the authenticated supplier.',
        }),
        ApiResponse({
            status: 200,
            description: 'Successfully retrieved supplier plan.',
            schema: {
                type: 'object',
                properties: {
                    plan: {
                        type: 'string',
                        enum: Object.values(SupplierPlan),
                        example: SupplierPlan.PREMIUM,
                    },
                },
                example: { plan: SupplierPlan.PREMIUM },
            },
        }),
        ApiNotFoundResponse({
            description: 'Supplier not found.',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Supplier not found.',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsSubscribePremium() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Subscribe to premium plan',
            description:
                'Upgrades the supplier account to the premium plan. Throws error if already on premium.',
        }),
        ApiResponse({
            status: 200,
            description: 'Successfully subscribed to premium plan.',
            schema: {
                type: 'object',
                properties: {
                    message: {
                        type: 'string',
                        example: 'Successfully subscribed to the premium plan.',
                    },
                    plan: {
                        type: 'string',
                        enum: Object.values(SupplierPlan),
                        example: SupplierPlan.PREMIUM,
                    },
                },
                example: {
                    message: 'Successfully subscribed to the premium plan.',
                    plan: SupplierPlan.PREMIUM,
                },
            },
        }),
        ApiResponse({
            status: 400,
            description: 'Supplier is already subscribed to premium.',
            schema: {
                example: {
                    statusCode: 400,
                    message: 'Supplier is already subscribed to premium.',
                    error: 'Bad Request',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'Supplier not found.',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Supplier not found.',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsStartFreeTrial() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Start free trial',
            description:
                'Starts the 30-day free trial for the supplier, upgrading to premium plan. Throws error if trial already used.',
        }),
        ApiResponse({
            status: 200,
            description: 'Successfully started free trial.',
            schema: {
                type: 'object',
                properties: {
                    message: {
                        type: 'string',
                        example:
                            'Free trial started successfully. You are now on the premium plan for 30 days.',
                    },
                    plan: {
                        type: 'string',
                        enum: Object.values(SupplierPlan),
                        example: SupplierPlan.PREMIUM,
                    },
                },
                example: {
                    message:
                        'Free trial started successfully. You are now on the premium plan for 30 days.',
                    plan: SupplierPlan.PREMIUM,
                },
            },
        }),
        ApiResponse({
            status: 400,
            description: 'Free trial has already been used.',
            schema: {
                example: {
                    statusCode: 400,
                    message: 'Free trial has already been used.',
                    error: 'Bad Request',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'Supplier not found.',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Supplier not found.',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsUpdateStoreBanner() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Update store banner',
            description:
                'Uploads a new store banner image for the authenticated supplier and updates their record.<br>' +
                '<strong>Note:</strong> The file must be an image (PNG, JPEG, WebP) and cannot exceed 5MB in size.<br>' +
                "<strong>IMPORTANT:</strong> Please ensure that uploaded images comply with Islamic laws. This means avoiding haram content such as music-related images, depictions of women's bodies (even hands), or any illustrations of living beings (humans, animals, etc.) whether drawn or digital.",
        }),
        ApiConsumes('multipart/form-data'),
        ApiBody({
            schema: {
                type: 'object',
                properties: {
                    file: {
                        type: 'string',
                        format: 'binary',
                        description: 'Banner image file to upload',
                    },
                },
                required: ['file'],
            },
        }),
        ApiResponse({
            status: 200,
            description: 'Store banner updated successfully.',
            schema: {
                type: 'object',
                properties: {
                    message: {
                        type: 'string',
                        example: 'Store banner updated successfully',
                    },
                    storeBannerFileName: {
                        type: 'string',
                        example: 'banner123-uuid.png',
                    },
                },
                example: {
                    message: 'Store banner updated successfully',
                    storeBannerFileName: 'banner123-uuid.png',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'Supplier not found.',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Supplier not found.',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsDeleteStoreBanner() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Delete store banner',
            description:
                'Deletes the current banner image for the supplier store.',
        }),
        ApiResponse({
            status: 200,
            description: 'Store banner deleted successfully.',
            schema: {
                type: 'object',
                properties: {
                    message: {
                        type: 'string',
                        example: 'Store banner deleted successfully',
                    },
                },
                example: { message: 'Store banner deleted successfully' },
            },
        }),
        ApiResponse({
            status: 400,
            description: 'No store banner to delete.',
            schema: {
                example: {
                    statusCode: 400,
                    message: 'No store banner to delete.',
                    error: 'Bad Request',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'Supplier not found.',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Supplier not found.',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsGetStoreBanner() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get store banner',
            description:
                'Retrieves the signed URL of the store banner for a given supplier ID.',
        }),
        ApiResponse({
            status: 200,
            description: 'Successfully retrieved store banner URL.',
            schema: {
                type: 'object',
                properties: {
                    storeBannerFileUrl: {
                        type: 'string',
                        format: 'uri',
                        example:
                            'https://cdn.example.com/banners/banner123.png',
                    },
                },
                example: {
                    storeBannerFileUrl:
                        'https://cdn.example.com/banners/banner123.png',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'No store banner found for this store.',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'No store banner found for this store.',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsGetAllSuppliers() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get all suppliers',
            description:
                'Retrieves a list of all suppliers, with optional filters by status (active/inactive) and subscription (subscribed/unsubscribed). ' +
                'Each element in the list can be either a full supplier DTO if active, or minimal inactive DTO if inactive.',
        }),
        ApiQuery({
            name: 'status',
            required: false,
            enum: ['active', 'inactive'],
            description: 'Filter suppliers by status',
            example: 'active',
        }),
        ApiQuery({
            name: 'subscription',
            required: false,
            enum: ['subscribed', 'unsubscribed'],
            description: 'Filter suppliers by subscription plan',
            example: 'subscribed',
        }),
        ApiResponse({
            status: 200,
            description: 'List of suppliers retrieved successfully.',
            schema: {
                type: 'array',
                items: {
                    oneOf: [
                        { $ref: getSchemaPath(SupplierResponseDto) },
                        { $ref: getSchemaPath(InactiveSupplierResponseDto) },
                    ],
                },
            },
        }),
    );
}

export function ApiDocsGetSupplierDataById() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get supplier data by ID',
            description:
                'Retrieves full supplier data including profile, store, subscription, and favorite categories. ' +
                'Returns either full supplier DTO if active, or minimal inactive DTO if inactive.',
        }),
        ApiParam({
            name: 'id',
            description: 'Unique ID of the supplier',
            example: 'uuid-1234',
        }),
        ApiResponse({
            status: 200,
            description: 'Supplier data retrieved successfully.',
            schema: {
                oneOf: [
                    { $ref: getSchemaPath(SupplierResponseDto) },
                    { $ref: getSchemaPath(InactiveSupplierResponseDto) },
                ],
            },
        }),
        ApiNotFoundResponse({
            description: 'Supplier with the given ID not found.',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Supplier with id 9932-we432 not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsGetSupplierStoreDataById() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get supplier storefront data',
            description:
                'Retrieves storefront-specific data for a supplier, suitable for displaying public store pages.',
        }),
        ApiParam({
            name: 'id',
            description: 'Unique ID of the supplier',
            example: 'uuid-1234',
        }),
        ApiResponse({
            status: 200,
            description: 'Storefront data retrieved successfully.',
            schema: {
                oneOf: [
                    { $ref: getSchemaPath(StorefrontResponseDto) },
                    { $ref: getSchemaPath(InactiveSupplierResponseDto) },
                ],
            },
        }),
        ApiNotFoundResponse({
            description: 'Supplier with the given ID not found.',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Supplier with id 9932-we432 not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}
