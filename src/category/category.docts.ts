import { applyDecorators } from '@nestjs/common';
import {
    ApiOperation,
    ApiOkResponse,
    ApiQuery,
    ApiNotFoundResponse,
    ApiHeader,
} from '@nestjs/swagger';
import { CategoryResponseDto } from './dtos/categoryResponse.dto';

/**
 * Common language query/header docs for category endpoints.
 * Use this in every endpoint decorator to stay consistent.
 */
function ApiDocsLanguageSupport() {
    return applyDecorators(
        ApiQuery({
            name: 'lang',
            description:
                "Optional language code for translation (e.g., `ar` or `en`). If omitted, system will use the user's preferred language or default to English.",
            required: false,
            example: 'ar',
        }),
        ApiHeader({
            name: 'accept-language',
            description:
                'Optional header to specify response translation language (e.g., `ar`, `en`). Used if `lang` query param not provided.',
            required: false,
            example: 'ar',
        }),
    );
}

export function ApiDocsGetAllCategories() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get all categories',
            description:
                'Returns all categories in the system (including nested subcategories). Supports translation via query parameter or header. Optionally, filter by `usedFor` (products or services).',
        }),
        ApiDocsLanguageSupport(),
        ApiQuery({
            name: 'usedFor',
            description: 'Filter categories by type (products or services)',
            required: false,
            example: 'products',
        }),
        ApiOkResponse({
            description:
                'List of all categories (translated if language specified).',
            type: [CategoryResponseDto],
            schema: {
                example: [
                    {
                        id: 1,
                        name: 'Agricultural & Pet Supplies',
                        usedFor: 'PRODUCT',
                        subcategories: [
                            {
                                id: 2,
                                name: 'Animal Feed',
                                usedFor: 'PRODUCT',
                                parentCategory: {
                                    id: 1,
                                    name: 'Agricultural & Pet Supplies',
                                },
                            },
                            {
                                id: 3,
                                name: 'Fertilizers',
                                usedFor: 'PRODUCT',
                                parentCategory: {
                                    id: 1,
                                    name: 'Agricultural & Pet Supplies',
                                },
                            },
                        ],
                    },
                ],
            },
        }),
    );
}

export function ApiDocsGetMainCategories() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get main (top-level) categories',
            description:
                'Returns only top-level categories (no parent). Supports translation via query parameter or header.',
        }),
        ApiDocsLanguageSupport(),
        ApiQuery({
            name: 'usedFor',
            description: 'Filter categories by type (products or services)',
            required: false,
            example: 'services',
        }),
        ApiOkResponse({
            description:
                'List of main categories (translated if language specified).',
            type: [CategoryResponseDto],
            schema: {
                example: [
                    {
                        id: 1,
                        name: 'Agricultural & Pet Supplies',
                        usedFor: 'PRODUCT',
                        subcategories: [
                            {
                                id: 2,
                                name: 'Animal Feed',
                                usedFor: 'PRODUCT',
                            },
                        ],
                    },
                ],
            },
        }),
    );
}

export function ApiDocsGetSubCategories() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get subcategories',
            description:
                'Returns only subcategories (categories that have a parent). Supports translation via query parameter or header.',
        }),
        ApiDocsLanguageSupport(),
        ApiQuery({
            name: 'usedFor',
            description: 'Filter subcategories by type (products or services)',
            required: false,
            example: 'products',
        }),
        ApiOkResponse({
            description:
                'List of subcategories (translated if language specified).',
            type: [CategoryResponseDto],
            schema: {
                example: [
                    {
                        id: 2,
                        name: 'Animal Feed',
                        usedFor: 'PRODUCT',
                        parentCategory: {
                            id: 1,
                            name: 'Agricultural & Pet Supplies',
                        },
                    },
                    {
                        id: 3,
                        name: 'Fertilizers',
                        usedFor: 'PRODUCT',
                        parentCategory: {
                            id: 1,
                            name: 'Agricultural & Pet Supplies',
                        },
                    },
                ],
            },
        }),
    );
}

export function ApiDocsGetCategoryById() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get category by ID',
            description:
                'Returns a single category by its ID (including its parent and all subcategories). Supports translation via query parameter or header.',
        }),
        ApiDocsLanguageSupport(),
        ApiQuery({
            name: 'id',
            description: 'The ID of the category to fetch',
            required: true,
            example: 1,
        }),
        ApiOkResponse({
            description: 'Category found (translated if language specified).',
            type: CategoryResponseDto,
            schema: {
                example: {
                    id: 1,
                    name: 'Agricultural & Pet Supplies',
                    usedFor: 'PRODUCT',
                    subcategories: [
                        {
                            id: 2,
                            name: 'Animal Feed',
                            usedFor: 'PRODUCT',
                            parentCategory: {
                                id: 1,
                                name: 'Agricultural & Pet Supplies',
                            },
                        },
                    ],
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'Category not found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Category with ID 1 not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}
