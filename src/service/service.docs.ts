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
import { ServiceResponseDto } from './dtos/serviceResponse.dto';
import { CreateServiceDto } from './dtos/createService.dto';

// ------------------------ CREATE SERVICE ------------------------
export function ApiDocsCreateService() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Create a new service',
            description: `<strong>IMPORTANT:</strong> This endpoint requires sending the data as <u>multipart/form-data</u>.<br>
                <strong>Note:</strong> Because this endpoint uses multipart/form-data, Swagger cannot directly show the CreateServiceDto schema here. 
                There is a separate Swagger-only endpoint (GET /create-service-dto) where you can view the full CreateServiceDto schema and example.<br><br>
                You must send two fields:
                <ul>
                    <li><strong>dto</strong> (type: text) → JSON string of the service details (see example below). 
                        <br>Check the Swagger-only endpoint for full schema reference.</li>
                    <li><strong>files</strong> → one or more image files (PNG, JPEG, WebP, max 5MB each, 1 to 10 files)</li>
                </ul>
                Only categories with <strong>usedFor=SERVICE</strong> can be assigned to services.`,
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
                                'Service images. 1 to 10 images allowed, formats: PNG, JPEG, WebP, max 5MB each.',
                        },
                    },
                    dto: {
                        type: 'string',
                        description:
                            'IMPORTANT: Must be a JSON string containing service details. ' +
                            'The JSON structure should follow CreateServiceDto format. ' +
                            'Check the Swagger-only endpoint GET /create-service-dto to see the full schema and example.',
                        example: JSON.stringify({
                            name: 'Home Cleaning Service',
                            description:
                                'Professional cleaning service for residential spaces.',
                            price: 99.99,
                            isPriceNegotiable: false,
                            categoryId: 12,
                            serviceAvailability: ['MONDAY', 'WEDNESDAY'],
                            isPublished: true,
                        }),
                    },
                },
                required: ['files', 'dto'],
            },
        }),
        ApiBody({
            type: CreateServiceDto,
            description: `<strong>⚠️ NOTE:</strong> This body is only for schema reference. 
            You must still send the service details as a JSON string in the 'dto' form field.`,
        }),
        ApiResponse({
            status: 201,
            description: 'Service created successfully',
            type: ServiceResponseDto,
        }),
        ApiBadRequestResponse({
            description: 'Invalid request (JSON, category, or file issues)',
            schema: {
                example: {
                    statusCode: 400,
                    message:
                        'Invalid JSON in form field OR Category not valid for services OR At least one service image is required',
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

export function ApiDocsFakeGetCreateServiceDto() {
    return applyDecorators(
        ApiOperation({
            deprecated: true,
            summary:
                '⚠️ ONLY for Swagger reference: shows CreateServiceDto schema',
            description: `⚠️ Swagger-only reference for CreateServiceDto schema. 
            This endpoint does not exist in the real API. Check the JSON structure for 'dto' in the multipart/form-data POST /services endpoint.`,
        }),
        ApiBody({
            description: 'Fake body showing CreateServiceDto',
            type: CreateServiceDto,
        }),
        ApiResponse({
            status: 200,
            description: 'This endpoint returns nothing',
        }),
    );
}

// ------------------------ GET SERVICES ------------------------
export function ApiDocsGetAllServices() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get all services',
            description: `Fetches all services. Optional query or header <strong>lang</strong> can be provided to translate service name and description.
                <ul>
                    <li>Header: <strong>accept-language</strong></li>
                    <li>Query: <strong>lang</strong></li>
                </ul>
                Defaults to English if not provided.`,
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
            description: 'List of services',
            type: [ServiceResponseDto],
        }),
    );
}

export function ApiDocsGetServiceById() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get service by ID',
            description: `Fetches a single service by its ID. Optional query or header <strong>lang</strong> can be provided to translate service name and description.
                Defaults to English if not provided.`,
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
            description: 'Service details',
            type: ServiceResponseDto,
        }),
        ApiNotFoundResponse({
            description: 'Service not found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Service with id 123 not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsGetAllSupplierServices() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get all services of a supplier',
            description: `Fetches all services for a given supplier. Optional query or header <strong>lang</strong> can be provided to translate service name and description.`,
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
            description: 'List of supplier services',
            type: [ServiceResponseDto],
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

// ------------------------ UPDATE SERVICE ------------------------
export function ApiDocsUpdateService() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Update a service',
            description: `Updates service fields (except images). Only provided fields will be updated. Requires Supplier role.`,
        }),
        ApiResponse({
            status: 200,
            description: 'Updated service details',
            type: ServiceResponseDto,
        }),
        ApiBadRequestResponse({
            description: 'Invalid request or invalid category',
            schema: {
                example: {
                    statusCode: 400,
                    message:
                        'Services must be assigned to a subcategory, not a main category',
                    error: 'Bad Request',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'Service or supplier not found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Service not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}

// ------------------------ UPDATE SERVICE IMAGE ------------------------
export function ApiDocsUpdateServiceImage() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Add a new image to an existing service',
            description: `This endpoint allows the supplier to add an additional image to an already created service.<br>
            Only the image is updated; other fields remain unchanged.<br>
            Maximum 3 images per service are allowed.`,
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
                            'Service image file (PNG, JPEG, WebP, max 5MB)',
                    },
                },
                required: ['file'],
            },
        }),
        ApiResponse({
            status: 200,
            description: 'Service with newly added image returned',
            type: ServiceResponseDto,
        }),
        ApiBadRequestResponse({
            description: 'Validation failed or max image limit exceeded',
            schema: {
                example: {
                    statusCode: 400,
                    message: 'A maximum of 3 service images is allowed',
                    error: 'Bad Request',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'Service or supplier not found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Service not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}

// ------------------------ DELETE SERVICE ------------------------
export function ApiDocsDeleteService() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Delete a service',
            description: 'Soft-deletes a service. Requires Supplier role.',
        }),
        ApiResponse({
            status: 200,
            description: 'Deletion confirmation',
            schema: { example: { message: 'Service deleted successfully' } },
        }),
        ApiNotFoundResponse({
            description: 'Service or supplier not found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Service not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}

// ------------------------ DELETE SERVICE IMAGE ------------------------
export function ApiDocsDeleteServiceImage() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Delete a specific service image',
            description:
                'Deletes a single image of a service. Requires at least one image to remain. Requires Supplier role.',
        }),
        ApiResponse({
            status: 200,
            description: 'Updated service details after deletion',
            type: ServiceResponseDto,
        }),
        ApiBadRequestResponse({
            description:
                'Invalid request (image not found or would leave service empty)',
            schema: {
                example: {
                    statusCode: 400,
                    message: 'A service must have at least one image.',
                    error: 'Bad Request',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'Service or supplier not found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Service not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}

// ------------------------ DUPLICATE SERVICE ------------------------
export function ApiDocsDuplicateService() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Duplicate a service',
            description:
                'Creates a copy of an existing service. The duplicated service is unpublished by default. Requires Supplier role.',
        }),
        ApiResponse({
            status: 201,
            description: 'Duplicated service details',
            type: ServiceResponseDto,
        }),
        ApiNotFoundResponse({
            description: 'Original service or supplier not found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Service not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}
