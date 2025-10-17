import { applyDecorators } from '@nestjs/common';
import {
    ApiOperation,
    ApiResponse,
    ApiBearerAuth,
    ApiBadRequestResponse,
    ApiNotFoundResponse,
    ApiBody,
    ApiQuery,
    ApiHeader,
} from '@nestjs/swagger';
import { OrderResponseDto } from './dtos/orderResponse.dto';
import { OrderStatus } from '@prisma/client';

export function ApiDocsGetMyOrders() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Get my orders',
            description: `Fetches orders for the authenticated user.
                <ul>
                    <li>If the user role is <strong>BUYER</strong>, returns orders placed by the buyer.</li>
                    <li>If the user role is <strong>SUPPLIER</strong>, returns orders received by the supplier.</li>
                </ul>
                <br>
                You can optionally filter the results by <code>status</code> (case-insensitive). 
                Example: <code>?status=pending</code> or <code>?status=DELIVERED</code>.`,
        }),
        ApiQuery({
            name: 'status',
            required: false,
            enum: OrderStatus,
            description: `Filter orders by status (case-insensitive). 
            <ul>
                ${Object.values(OrderStatus)
                    .map((s) => `<li><code>${s}</code></li>`)
                    .join('')}
            </ul>
            If omitted, all orders are returned.`,
            example: 'pending',
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
            description: 'List of orders',
            type: [OrderResponseDto],
        }),
        ApiBadRequestResponse({
            description: 'Invalid query or unsupported order status.',
            schema: {
                example: {
                    statusCode: 400,
                    message: 'Invalid order status: shippeded',
                    error: 'Bad Request',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'User not found or orders not found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'User not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsGetOrderById() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Get order by ID',
            description: `Fetches a single order by its ID. Only accessible by the buyer or supplier related to the order.`,
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
            description: 'Order details',
            type: OrderResponseDto,
        }),
        ApiNotFoundResponse({
            description: 'Order not found for this user',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Order not found for this buyer',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsUpdateOrderStatus() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Update order status',
            description: `Allows a supplier to update the status of an order. 
                <strong>Suppliers cannot set status to COMPLETED.</strong>`,
        }),
        ApiBody({
            schema: {
                type: 'object',
                properties: {
                    newStatus: {
                        type: 'string',
                        enum: ['PENDING', 'PROCESSING', 'SHIPPED'],
                        description: 'New order status (cannot be COMPLETED)',
                        example: 'PROCESSING',
                    },
                },
                required: ['newStatus'],
            },
        }),
        ApiResponse({
            status: 200,
            description: 'Order status updated successfully',
            schema: {
                example: {
                    message: 'Order status updated successfully',
                    newStatus: 'PROCESSING',
                },
            },
        }),
        ApiBadRequestResponse({
            description: 'Invalid status or not allowed',
            schema: {
                example: {
                    statusCode: 400,
                    message:
                        'Invalid order status. Valid statuses: PENDING, PROCESSING, SHIPPED',
                    error: 'Bad Request',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'Order or supplier not found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Order not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsConfirmDelivery() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Confirm delivery',
            description: `Allows a buyer to confirm the delivery of their order. 
                Status will be updated to <strong>COMPLETED</strong>.`,
        }),
        ApiResponse({
            status: 200,
            description: 'Delivery confirmed successfully',
            schema: {
                example: {
                    message: 'Order delivery confirmed successfully',
                    newStatus: 'COMPLETED',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'Order or buyer not found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Order not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}
