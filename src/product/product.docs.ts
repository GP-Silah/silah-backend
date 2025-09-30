import { applyDecorators } from '@nestjs/common';
import {
    ApiOperation,
    ApiResponse,
    ApiBearerAuth,
    ApiConsumes,
    ApiBody,
    ApiNotFoundResponse,
    ApiBadRequestResponse,
    ApiQuery,
    ApiHeader,
} from '@nestjs/swagger';
import { ProductResponseDto } from './dtos/productResponse.dto';
import { CreateProductDto } from './dtos/createProduct.dto';

export function ApiDocsCreateProduct() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Create a new product',
            description: `<strong>IMPORTANT:</strong> This endpoint requires sending the data as <u>multipart/form-data</u>.<br>
                <strong>Note:</strong> Because this endpoint uses multipart/form-data, Swagger cannot directly show the CreateProductDto schema here. 
                There is a separate Swagger-only endpoint (GET /swagger-products-reference/create-product-dto) where you can view the full CreateProductDto schema and example.<br><br>
                You must send two fields:
                <ul>
                    <li><strong>dto</strong> (type: text) → JSON string of the product details (see example below). 
                    <br>Check the Swagger-only endpoint for full schema reference.</li>
                    <li><strong>files</strong> → one or more image files (PNG, JPEG, WebP, max 5MB each, 1 to 3 files)</li>
                </ul>
                Make sure the JSON string is properly formatted.<br><br>
                Only subcategories can be assigned to products. Main categories are invalid.<br><br>
                <strong>Note:</strong> The file must be an image (PNG, JPEG, WebP) and cannot exceed 5MB in size.<br>
                <strong>IMPORTANT:</strong> Please ensure that uploaded images comply with Islamic laws. This means avoiding haram content such as music-related images, depictions of women's bodies (even hands), or any illustrations of living beings (humans, animals, etc.) whether drawn or digital.`,
        }),
        ApiConsumes('multipart/form-data'),
        ApiBody({
            schema: {
                type: 'object',
                properties: {
                    files: {
                        type: 'array',
                        items: {
                            type: 'string',
                            format: 'binary',
                            description:
                                'Product images. 1 to 3 images allowed, formats: PNG, JPEG, WebP, max 5MB each.',
                        },
                    },
                    dto: {
                        type: 'string',
                        description:
                            'IMPORTANT: Must be a JSON string containing product details. ' +
                            'The JSON structure should follow CreateProductDto format. ' +
                            'Check the Swagger-only endpoint GET /swagger-products-reference/create-product-dto to see the full schema and example.',
                        example: JSON.stringify({
                            name: 'Classic Wooden Hair Brush',
                            description:
                                'Durable wooden hair brush with soft bristles, designed for daily styling and gentle scalp massage.',
                            price: 24.99,
                            stock: 150,
                            categoryId: 21,
                            caseQuantity: 12,
                            minOrderQuantity: 1,
                            maxOrderQuantity: 10,
                            allowGroupPurchase: true,
                            minGroupOrderQuantity: 5,
                            groupPurchasePrice: 19.99,
                            groupPurchaseDuration: 'FIVE_DAYS',
                            isPublished: true,
                        }),
                    },
                },
                required: ['files', 'dto'],
            },
        }),
        ApiBody({
            // fake body just to show schema
            type: CreateProductDto,
            description: `<strong>⚠️ NOTE:</strong> This body will NOT actually work if you try to send it as JSON. 
            It is here ONLY so the schema appears in Swagger for reference. 
            You must still send the product details as a JSON string in the 'dto' form field. 
            You can also check the Swagger-only endpoint GET /swagger-products-reference/create-product-dto to view the schema.`,
        }),
        ApiResponse({
            status: 201,
            description: 'Product created successfully',
            type: ProductResponseDto,
        }),
        ApiBadRequestResponse({
            description:
                'Invalid request. Could be invalid JSON, missing fields, invalid category, or file issues.',
            schema: {
                example: {
                    statusCode: 400,
                    message:
                        'Invalid JSON in form field OR Products must be assigned to a subcategory, not a main category OR At least one product image is required',
                    error: 'Bad Request',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'Supplier or category not found',
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

export function ApiDocsFakeGetCreateProductDto() {
    return applyDecorators(
        ApiOperation({
            deprecated: true,
            summary:
                '⚠️ ONLY for Swagger reference: shows CreateProductDto schema',
            description: `⚠️ IMPORTANT: This endpoint is a Swagger-only reference and does NOT exist in the real API.<br>
            It is here solely so you can view the full CreateProductDto schema and example in the Swagger Schemas panel.<br>
            You cannot actually call this endpoint, doing so will return nothing if attempted.<br><br>
            Why does this exist?<br>
            The real "Create Product" endpoint uses multipart/form-data to accept files and a JSON string,
            which means Swagger cannot automatically show the CreateProductDto schema for that endpoint.<br>
            This fake endpoint is a workaround to let you inspect the expected JSON structure, see required fields, 
            and understand how to format your requests when sending the 'dto' field as a JSON string in the real API.<br><br>
            Use this purely as a reference to know:<br>
            - All required and optional fields<br>
            - Field types and valid values<br>
            - Example data for testing<br><br>
            DO NOT use this in your frontend code or try to send requests to it.<br>
            Always send product data as a JSON string in the 'dto' field of the real multipart/form-data endpoint.`,
        }),
        ApiBody({
            description: 'Fake body showing CreateProductDto',
            type: CreateProductDto,
        }),
        ApiResponse({
            status: 200,
            description: 'This endpoint returns nothing',
        }),
    );
}

export function ApiDocsGetAllProducts() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get all products',
            description: `Fetches all products. Optional query or header <strong>lang</strong> can be provided to translate product name and description.
                <ul>
                    <li>Header: <strong>accept-language</strong></li>
                    <li>Query: <strong>lang</strong></li>
                </ul>
                If no language is provided, defaults to English.`,
        }),
        ApiHeader({
            name: 'accept-language',
            required: false,
            description:
                'Optional header to specify target language for translation (ar or en)',
            schema: { enum: ['ar', 'en'] },
        }),
        ApiQuery({
            name: 'lang',
            required: false,
            enum: ['ar', 'en'],
            description: 'Target language for translation',
        }),
        ApiResponse({
            status: 200,
            description: 'List of products',
            type: [ProductResponseDto],
        }),
    );
}

export function ApiDocsGetProductById() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get product by ID',
            description: `Fetches a single product by its ID. Optional query or header <strong>lang</strong> can be provided to translate product name and description.
                <ul>
                    <li>Header: <strong>accept-language</strong></li>
                    <li>Query: <strong>lang</strong></li>
                </ul>
                If no language is provided, defaults to English.`,
        }),
        ApiHeader({
            name: 'accept-language',
            required: false,
            description:
                'Optional header to specify target language for translation (ar or en)',
            schema: { enum: ['ar', 'en'] },
        }),
        ApiQuery({
            name: 'lang',
            required: false,
            enum: ['ar', 'en'],
            description: 'Target language for translation',
        }),
        ApiResponse({
            status: 200,
            description: 'Product details',
            type: ProductResponseDto,
        }),
        ApiNotFoundResponse({
            description: 'Product not found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Product with id 123 not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsGetAllSupplierProducts() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get all products of a supplier',
            description: `Fetches all products for a given supplier. Optional query or header <strong>lang</strong> can be provided to translate product name and description.
                <ul>
                    <li>Header: <strong>accept-language</strong></li>
                    <li>Query: <strong>lang</strong></li>
                </ul>
                If no language is provided, defaults to English.`,
        }),
        ApiHeader({
            name: 'accept-language',
            required: false,
            description:
                'Optional header to specify target language for translation (ar or en)',
            schema: { enum: ['ar', 'en'] },
        }),
        ApiQuery({
            name: 'lang',
            required: false,
            enum: ['ar', 'en'],
            description: 'Target language for translation',
        }),
        ApiResponse({
            status: 200,
            description: 'List of supplier products',
            type: [ProductResponseDto],
        }),
        ApiNotFoundResponse({
            description: 'Supplier not found',
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

export function ApiDocsUpdateProduct() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Update a product',
            description: `Updates product fields (except images). Only the fields provided in the request body will be updated. Requires Supplier role.`,
        }),
        ApiResponse({
            status: 200,
            description: 'Updated product details',
            type: ProductResponseDto,
        }),
        ApiBadRequestResponse({
            description: 'Invalid request or invalid category',
            schema: {
                example: {
                    statusCode: 400,
                    message:
                        'Products must be assigned to a subcategory, not a main category',
                    error: 'Bad Request',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'Product or supplier not found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Product not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsUpdateProductImage() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Add a new image to an existing product',
            description: `This endpoint allows the supplier to add an additional image to an already created product.<br>
            Only the image is updated; product name, description, and other fields remain unchanged.<br>
            Maximum 3 images per product are allowed.<br><br>
            <strong>Note:</strong> The file must be an image (PNG, JPEG, WebP) and cannot exceed 5MB in size.<br>
            <strong>IMPORTANT:</strong> Please ensure that uploaded images comply with Islamic laws. This means avoiding haram content such as music-related images, depictions of women's bodies (even hands), or any illustrations of living beings (humans, animals, etc.) whether drawn or digital.`,
        }),
        ApiConsumes('multipart/form-data'),
        ApiBody({
            schema: {
                type: 'object',
                properties: {
                    file: {
                        type: 'string',
                        format: 'binary',
                        description:
                            'The product image file (PNG, JPEG, WebP, max 5MB)',
                    },
                },
                required: ['file'],
            },
        }),
        ApiResponse({
            status: 200,
            description: 'The product with the newly added image is returned',
            type: ProductResponseDto,
        }),
        ApiBadRequestResponse({
            description: 'Validation failed or maximum image limit exceeded',
            schema: {
                example: {
                    statusCode: 400,
                    message: 'A maximum of 3 product images is allowed',
                    error: 'Bad Request',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'Supplier or product not found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Product not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsDeleteProduct() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Delete a product',
            description: 'Soft-deletes a product. Requires Supplier role.',
        }),
        ApiResponse({
            status: 200,
            description: 'Deletion confirmation',
            schema: {
                example: { message: 'Product deleted successfully' },
            },
        }),
        ApiNotFoundResponse({
            description: 'Product or supplier not found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Product not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsDeleteProductImage() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Delete a specific product image',
            description:
                'Deletes a single image of a product. Requires at least one image to remain. Requires Supplier role.',
        }),
        ApiResponse({
            status: 200,
            description: 'Updated product details after deletion',
            type: ProductResponseDto,
        }),
        ApiBadRequestResponse({
            description:
                'Invalid request (image not found or would leave product empty)',
            schema: {
                example: {
                    statusCode: 400,
                    message: 'A product must have at least one image.',
                    error: 'Bad Request',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'Product or supplier not found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Product not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsDuplicateProduct() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Duplicate a product',
            description:
                'Creates a copy of an existing product. The duplicated product is unpublished by default. Requires Supplier role.',
        }),
        ApiResponse({
            status: 201,
            description: 'Duplicated product details',
            type: ProductResponseDto,
        }),
        ApiNotFoundResponse({
            description: 'Original product or supplier not found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Product not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}
