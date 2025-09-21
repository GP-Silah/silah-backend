import { applyDecorators } from '@nestjs/common';
import {
    ApiOperation,
    ApiResponse,
    ApiBearerAuth,
    ApiBody,
    ApiConsumes,
    ApiParam,
    ApiQuery,
} from '@nestjs/swagger';
import { SupplierResponseDto } from './dtos/supplierResponse.dto';
import { StoreStatus, SupplierPlan, SupplierStatus } from '@prisma/client';
import { UpdateSupplierDto } from './dtos/updateSupplier.dto';
import { StorefrontResponseDto } from './dtos/storefrontResponse.dto';

export function ApiDocsGetMySupplierData() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Get current supplier profile',
            description:
                'Retrieves the supplier data of the authenticated user. Includes linked user information.',
        }),
        ApiResponse({
            status: 200,
            description: 'Successfully retrieved supplier profile.',
            type: SupplierResponseDto,
            schema: {
                example: {
                    user: {
                        id: 'uuid-user-1234',
                        name: 'John Doe',
                        email: 'john@gmail.com',
                        phone: '+966500000000',
                        role: 'SUPPLIER',
                        createdAt: '2025-08-15T12:00:00.000Z',
                    },
                    supplierId: 'uuid-supplier-5678',
                    supplierName: 'John Doe',
                    supplierEmail: 'john@gmail.com',
                    businessName: 'John Bakery',
                    city: 'Riyadh',
                    storeStatus: StoreStatus.OPEN,
                    storeClosedMsg: null,
                    storeBio: 'We specialize in handmade bakery items.',
                    storeBannerFileName:
                        'banner123-6963ac71-3e92-441d-badd-a57b4a99b2e5.png',
                    storeBannerFileUrl:
                        'https://cdn.example.com/banners/banner123.png',
                    deliveryFees: 15.5,
                    avgRating: 4.5,
                    ratingsCount: 23,
                    usedFreeTrail: true,
                    supplierStatus: SupplierStatus.ACTIVE,
                    plan: SupplierPlan.PREMIUM,
                    favoriteCategories: [
                        { id: 16, name: 'Animal Feed' },
                        { id: 33, name: 'Jewelry & Watches' },
                    ],
                },
            },
        }),
        ApiResponse({
            status: 404,
            description: 'Supplier not found for the given user.',
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
            type: StorefrontResponseDto,
            schema: {
                example: {
                    supplierId: 'uuid-supplier-5678',
                    supplierName: 'John Doe',
                    supplierEmail: 'john@gmail.com',
                    businessName: 'John Bakery',
                    city: 'Riyadh',
                    storeStatus: 'OPEN',
                    storeClosedMsg: 'We are closed for Eid holidays.',
                    storeBio: 'We specialize in handmade bakery items.',
                    storeBannerFileName:
                        'banner123-6963ac71-3e92-441d-badd-a57b4a99b2e5.png',
                    storeBannerFileUrl:
                        'https://cdn.example.com/banners/banner123.png',
                    deliveryFees: 15.5,
                    avgRating: 4.5,
                    ratingsCount: 23,
                    supplierStatus: 'ACTIVE',
                },
            },
        }),
        ApiResponse({
            status: 404,
            description: 'Supplier not found for the given user.',
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
            schema: {
                example: {
                    user: {
                        id: 'uuid-user-1234',
                        name: 'John Doe',
                        email: 'john@gmail.com',
                        phone: '+966500000000',
                        role: 'SUPPLIER',
                        createdAt: '2025-08-15T12:00:00.000Z',
                    },
                    supplierId: 'uuid-supplier-5678',
                    supplierName: 'John Doe',
                    supplierEmail: 'john@gmail.com',
                    businessName: 'John Bakery',
                    city: 'Riyadh',
                    storeStatus: 'OPEN',
                    storeClosedMsg: 'We are closed for Eid holidays.',
                    storeBio: 'We specialize in handmade bakery items.',
                    storeBannerFileName:
                        'banner123-6963ac71-3e92-441d-badd-a57b4a99b2e5.png',
                    storeBannerFileUrl:
                        'https://cdn.example.com/banners/banner123.png',
                    deliveryFees: 20,
                    avgRating: 4.7,
                    ratingsCount: 30,
                    usedFreeTrail: true,
                    supplierStatus: 'ACTIVE',
                    plan: 'PREMIUM',
                    favoriteCategories: [
                        { id: 16, name: 'Animal Feed' },
                        { id: 33, name: 'Jewelry & Watches' },
                    ],
                },
            },
        }),
        ApiResponse({
            status: 404,
            description: 'Supplier not found for the given user.',
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
        ApiResponse({
            status: 404,
            description:
                'Supplier not found when fetching favorite categories.',
        }),
    );
}

export function ApiDocsToggleFavoriteCategory() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Toggle a favorite category for supplier',
            description:
                'Adds a category to the supplier’s favorite categories if not already present, or removes it if already present. Returns a message and updated favorite categories list.',
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
        }),
        ApiResponse({
            status: 404,
            description: 'Supplier not found.',
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
        ApiResponse({
            status: 404,
            description: 'Supplier not found.',
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
        }),
        ApiResponse({
            status: 404,
            description: 'Supplier not found.',
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
        }),
        ApiResponse({
            status: 404,
            description: 'Supplier not found.',
        }),
    );
}

export function ApiDocsUpdateStoreBanner() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Update store banner',
            description:
                'Uploads a new banner image for the supplier store. Max size 5MB. Accepted types: png, jpg, jpeg, webp.',
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
        ApiResponse({
            status: 404,
            description: 'Supplier not found.',
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
        }),
        ApiResponse({
            status: 404,
            description: 'Supplier not found.',
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
        ApiResponse({
            status: 404,
            description: 'No store banner found for this store.',
        }),
    );
}

export function ApiDocsGetAllSuppliers() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get all suppliers',
            description:
                'Retrieves a list of all suppliers, with optional filters by status (active/inactive) and subscription (subscribed/unsubscribed).',
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
            type: SupplierResponseDto,
            isArray: true,
        }),
    );
}

export function ApiDocsGetSupplierDataById() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get supplier data by ID',
            description:
                'Retrieves full supplier data including profile, store, subscription, and favorite categories.',
        }),
        ApiParam({
            name: 'id',
            description: 'Unique ID of the supplier',
            example: 'uuid-1234',
        }),
        ApiResponse({
            status: 200,
            description: 'Supplier data retrieved successfully.',
            type: SupplierResponseDto,
        }),
        ApiResponse({
            status: 404,
            description: 'Supplier with the given ID not found.',
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
            type: StorefrontResponseDto,
        }),
        ApiResponse({
            status: 404,
            description: 'Supplier with the given ID not found.',
        }),
    );
}
