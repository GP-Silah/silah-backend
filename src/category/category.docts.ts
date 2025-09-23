import { applyDecorators } from '@nestjs/common';
import {
    ApiOperation,
    ApiOkResponse,
    ApiQuery,
    ApiNotFoundResponse,
} from '@nestjs/swagger';
import { CategoryResponseDto } from './dtos/categoryResponse.dto';

export function ApiDocsGetAllCategories() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get all categories',
            description:
                'Returns all categories in the system, including nested subcategories. Optionally, filter by `usedFor` (products or services).',
        }),
        ApiQuery({
            name: 'usedFor',
            description: 'Filter categories by type',
            required: false,
            example: 'products',
        }),
        ApiOkResponse({
            description: 'List of all categories',
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
                            {
                                id: 4,
                                name: 'Pet Accessories & Toys',
                                usedFor: 'PRODUCT',
                                parentCategory: {
                                    id: 1,
                                    name: 'Agricultural & Pet Supplies',
                                },
                            },
                            {
                                id: 5,
                                name: 'Pet Food & Treats',
                                usedFor: 'PRODUCT',
                                parentCategory: {
                                    id: 1,
                                    name: 'Agricultural & Pet Supplies',
                                },
                            },
                        ],
                    },
                    {
                        id: 20,
                        name: 'Software & IT Solutions',
                        usedFor: 'SERVICE',
                        subcategories: [
                            {
                                id: 21,
                                name: 'Web & App Development',
                                usedFor: 'SERVICE',
                                parentCategory: {
                                    id: 20,
                                    name: 'Software & IT Solutions',
                                },
                            },
                            {
                                id: 22,
                                name: 'IT & Cloud Services',
                                usedFor: 'SERVICE',
                                parentCategory: {
                                    id: 20,
                                    name: 'Software & IT Solutions',
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
                'Returns only the top-level categories (no parent) in the system, optionally filtered by `usedFor`.',
        }),
        ApiQuery({
            name: 'usedFor',
            description: 'Filter categories by type',
            required: false,
            example: 'services',
        }),
        ApiOkResponse({
            description: 'List of top-level categories',
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
                            {
                                id: 4,
                                name: 'Pet Accessories & Toys',
                                usedFor: 'PRODUCT',
                                parentCategory: {
                                    id: 1,
                                    name: 'Agricultural & Pet Supplies',
                                },
                            },
                            {
                                id: 5,
                                name: 'Pet Food & Treats',
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

export function ApiDocsGetSubCategories() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get subcategories',
            description:
                'Returns only subcategories (categories that have a parent), optionally filtered by `usedFor`.',
        }),
        ApiQuery({
            name: 'usedFor',
            description: 'Filter subcategories by type',
            required: false,
            example: 'products',
        }),
        ApiOkResponse({
            description: 'List of subcategories',
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
                    {
                        id: 21,
                        name: 'Web & App Development',
                        usedFor: 'SERVICE',
                        parentCategory: {
                            id: 20,
                            name: 'Software & IT Solutions',
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
                'Returns a single category by its ID, including its parent category and all nested subcategories.',
        }),
        ApiQuery({
            name: 'id',
            description: 'The ID of the category to fetch',
            required: true,
            example: 1,
        }),
        ApiOkResponse({
            description: 'Category found',
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
                        {
                            id: 3,
                            name: 'Fertilizers',
                            usedFor: 'PRODUCT',
                            parentCategory: {
                                id: 1,
                                name: 'Agricultural & Pet Supplies',
                            },
                        },
                        {
                            id: 4,
                            name: 'Pet Accessories & Toys',
                            usedFor: 'PRODUCT',
                            parentCategory: {
                                id: 1,
                                name: 'Agricultural & Pet Supplies',
                            },
                        },
                        {
                            id: 5,
                            name: 'Pet Food & Treats',
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
                    message: 'Category not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}
