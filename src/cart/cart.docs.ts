import { applyDecorators } from '@nestjs/common';
import {
    ApiBearerAuth,
    ApiOperation,
    ApiOkResponse,
    ApiBadRequestResponse,
    ApiNotFoundResponse,
    ApiBody,
    ApiParam,
    ApiQuery,
    ApiHeader,
} from '@nestjs/swagger';
import { CartResponseDto } from './dtos/cartResponse.dto';
import { AddCartItemDto } from './dtos/addCartItem.dto';

export function ApiDocsGetBuyerActiveCart() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Get active cart for buyer',
            description:
                'Fetches the currently active cart of the authenticated buyer. ' +
                'Returns details of suppliers, items, and totals. ' +
                'Throws 404 if no active cart exists.' +
                'Supports optional language selection via header or query.',
        }),
        ApiQuery({
            name: 'lang',
            required: false,
            description: 'Optional query param to set language (ar | en)',
            enum: ['ar', 'en'],
        }),
        ApiHeader({
            name: 'accept-language',
            required: false,
            description: 'Optional header to set language (ar | en)',
            enum: ['ar', 'en'],
        }),
        ApiOkResponse({
            description: 'Active cart retrieved successfully',
            type: CartResponseDto,
        }),
        ApiNotFoundResponse({
            description: 'No active cart found for this buyer',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'No active cart for this buyer',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsAddCartItem() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Add item to cart',
            description:
                "Adds a product to the buyer's active cart. " +
                'If no cart exists, a new one is automatically created. ' +
                'Groups items by supplier.',
        }),
        ApiBody({ type: AddCartItemDto }),
        ApiOkResponse({
            description: 'Item added to cart successfully',
            type: CartResponseDto,
        }),
        ApiBadRequestResponse({
            description: 'Invalid supplier or input data',
            schema: {
                example: {
                    statusCode: 400,
                    message: 'Supplier with id 123 not found',
                    error: 'Bad Request',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'Product or buyer not found',
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

export function ApiDocsUpdateItemQuantity() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Update item quantity in cart',
            description:
                "Updates the quantity of a specific item in the buyer's cart. " +
                'Recalculates supplier subtotal and cart totals.',
        }),
        ApiParam({ name: 'cartId', type: String, description: 'Cart ID' }),
        ApiParam({ name: 'itemId', type: Number, description: 'Cart Item ID' }),
        ApiBody({
            schema: {
                type: 'object',
                properties: {
                    newQuantity: { type: 'number', example: 3 },
                },
            },
        }),
        ApiOkResponse({
            description: 'Item quantity updated successfully',
            type: CartResponseDto,
        }),
        ApiBadRequestResponse({
            description: 'Invalid new quantity',
            schema: {
                example: {
                    statusCode: 400,
                    message: 'New quantity cannot be null or less than 1',
                    error: 'Bad Request',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'Cart or item not found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Item not found in this cart',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsRemoveItem() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Remove item from cart',
            description:
                "Deletes a specific item from the buyer's cart. " +
                'If the supplier group has no items left, the supplier is also removed from the cart.',
        }),
        ApiParam({ name: 'cartId', type: String, description: 'Cart ID' }),
        ApiParam({ name: 'itemId', type: Number, description: 'Cart Item ID' }),
        ApiOkResponse({
            description: 'Item removed successfully',
            type: CartResponseDto,
        }),
        ApiNotFoundResponse({
            description: 'Cart or item not found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Item not found in this cart',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsDeleteCart() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Delete entire cart',
            description:
                "Marks the buyer's cart as deleted. " +
                'Once deleted, the cart cannot be retrieved as active.',
        }),
        ApiParam({ name: 'cartId', type: String, description: 'Cart ID' }),
        ApiOkResponse({
            description: 'Cart deleted successfully',
            schema: {
                example: { message: 'Cart deleted successfully' },
            },
        }),
        ApiNotFoundResponse({
            description: 'Cart not found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Cart not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsRemoveSupplierFromCart() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Remove supplier (and its items) from cart',
            description:
                'Removes all items from a specific supplier in the cart. ' +
                'If the supplier is the last one, the whole cart is deleted.',
        }),
        ApiParam({ name: 'cartId', type: String, description: 'Cart ID' }),
        ApiParam({
            name: 'supplierId',
            type: String,
            description: 'Supplier ID',
        }),
        ApiOkResponse({
            description: 'Supplier removed successfully, updated cart returned',
            type: CartResponseDto,
        }),
        ApiNotFoundResponse({
            description: 'Supplier or cart not found',
            schema: {
                oneOf: [
                    {
                        example: {
                            statusCode: 404,
                            message: 'Supplier not found in this cart',
                            error: 'Not Found',
                        },
                    },
                    {
                        example: {
                            statusCode: 404,
                            message: 'Cart is now empty and has been deleted',
                            error: 'Not Found',
                        },
                    },
                ],
            },
        }),
    );
}

export function ApiDocsCheckoutCart() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Checkout cart',
            description:
                "Finalizes the buyer's cart by creating orders for each supplier. " +
                'Marks the cart as bought and returns the checkout details. ' +
                'Payment integration (Tap) will be handled here.',
        }),
        ApiParam({ name: 'cartId', type: String, description: 'Cart ID' }),
        ApiOkResponse({
            description: 'Cart checked out successfully',
            schema: {
                example: {
                    message: 'Paid successfully',
                    checkoutId: 'uuid-checkout-id',
                    buyerId: 'uuid-buyer-id',
                    cartId: 'uuid-cart-id',
                    totalPaid: 250,
                    orders: [
                        {
                            id: 'uuid-order-1',
                            supplierId: 'uuid-supplier-id',
                            finalPrice: 150,
                            status: 'PENDING',
                        },
                        {
                            id: 'uuid-order-2',
                            supplierId: 'uuid-supplier-id-2',
                            finalPrice: 100,
                            status: 'PENDING',
                        },
                    ],
                },
            },
        }),
        ApiBadRequestResponse({
            description: 'Cart is empty',
            schema: {
                example: {
                    statusCode: 400,
                    message: 'Cart is empty',
                    error: 'Bad Request',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'Active cart not found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Active cart not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}
