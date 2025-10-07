import { applyDecorators } from '@nestjs/common';
import { ApiOkResponse, ApiOperation, ApiQuery } from '@nestjs/swagger';
import { ProductResponseDto } from 'src/product/dtos/productResponse.dto';
import { ServiceResponseDto } from 'src/service/dtos/serviceResponse.dto';
import { SupplierResponseDto } from 'src/supplier/dtos/supplierResponse.dto';
import { UserResponseDTO } from 'src/user/dtos/userResponse.dto';

export function ApiDocsGetSearchUsers() {
    return applyDecorators(
        ApiOperation({
            summary: 'Search users by name',
            description:
                'Performs fuzzy and full-text search on user names and returns matching users.',
        }),
        ApiQuery({
            name: 'name',
            type: String,
            description: 'Full or partial user name to search for',
            example: 'Sarah',
            required: false,
        }),
        ApiOkResponse({
            description: 'List of matching users',
            type: [UserResponseDTO],
        }),
    );
}

export function ApiDocsGetSearchSuppliers() {
    return applyDecorators(
        ApiOperation({
            summary: 'Search suppliers by name or business name',
            description:
                'Returns a list of suppliers whose name or business name partially matches the query. Supports fuzzy and full-text search.',
        }),
        ApiQuery({
            name: 'name',
            type: String,
            description: 'Supplier user name (optional)',
            example: 'Shahad',
            required: false,
        }),
        ApiQuery({
            name: 'businessName',
            type: String,
            description: 'Supplier business name (optional)',
            example: 'ShahadSaad001',
            required: false,
        }),
        ApiOkResponse({
            description: 'List of matching suppliers',
            type: [SupplierResponseDto],
        }),
    );
}

export function ApiDocsGetSearchProducts() {
    return applyDecorators(
        ApiOperation({
            summary: 'Search products by name, category, or price range',
            description: `
Performs fuzzy search on product names and allows filtering by:
- **Main category** or **subcategory**
- **Minimum** and/or **maximum price**

Returned products are only those that are **published** and **not deleted**.
`,
        }),
        ApiQuery({
            name: 'name',
            type: String,
            description: 'Product name or part of it (optional)',
            example: 'Wooden Brush',
            required: false,
        }),
        ApiQuery({
            name: 'category',
            type: String,
            description: 'Main category ID (optional)',
            example: '1',
            required: false,
        }),
        ApiQuery({
            name: 'subcategory',
            type: String,
            description: 'Subcategory ID (optional)',
            example: '5',
            required: false,
        }),
        ApiQuery({
            name: 'minPrice',
            type: String,
            description: 'Minimum product price (SAR, optional)',
            example: '10',
            required: false,
        }),
        ApiQuery({
            name: 'maxPrice',
            type: String,
            description: 'Maximum product price (SAR, optional)',
            example: '100',
            required: false,
        }),
        ApiOkResponse({
            description: 'List of matching products',
            type: [ProductResponseDto],
        }),
    );
}

export function ApiDocsGetSearchServices() {
    return applyDecorators(
        ApiOperation({
            summary: 'Search services by name or category',
            description:
                'Performs fuzzy search on service names and filters by main or subcategory. Returns only published and active services.',
        }),
        ApiQuery({
            name: 'name',
            type: String,
            description: 'Service name or part of it (optional)',
            example: 'Makeup',
            required: false,
        }),
        ApiQuery({
            name: 'category',
            type: String,
            description: 'Main category ID (optional)',
            example: '2',
            required: false,
        }),
        ApiQuery({
            name: 'subcategory',
            type: String,
            description: 'Subcategory ID (optional)',
            example: '4',
            required: false,
        }),
        ApiOkResponse({
            description: 'List of matching services',
            type: [ServiceResponseDto],
        }),
    );
}
