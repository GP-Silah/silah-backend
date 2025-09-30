import { applyDecorators } from '@nestjs/common';
import {
    ApiBearerAuth,
    ApiOperation,
    ApiOkResponse,
    ApiBadRequestResponse,
    ApiNotFoundResponse,
    ApiBody,
    ApiParam,
} from '@nestjs/swagger';
import { CartResponseDto } from './dtos/cartResponse.dto';
import { AddCartItemDto } from './dtos/addCartItem.dto';

export function ApiDocsGetBuyerActiveCart() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Get active cart for buyer',
            description:
                'Fetches the currently active cart of the authenticated buyer, including suppliers, items, and totals. ' +
                'Throws 404 if no active cart exists.',
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
                    message: 'No active cart found for this buyer',
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
                "Adds a product to the buyer's active cart. If no cart exists, a new one is created. " +
                'Items are grouped by supplier automatically.',
        }),
        ApiBody({ type: AddCartItemDto }),
        ApiOkResponse({
            description: 'Item added to cart successfully',
            type: CartResponseDto,
        }),
        ApiBadRequestResponse({
            description:
                'Invalid supplier or input data, or requested quantity exceeds stock',
            schema: {
                example: {
                    statusCode: 400,
                    message: 'Supplier for this product not found',
                    error: 'Bad Request',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'Buyer or product not found',
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
                "Updates the quantity of a specific item in the buyer's cart and recalculates totals.",
        }),
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
            description: 'Quantity is invalid or exceeds product stock',
            schema: {
                example: {
                    statusCode: 400,
                    message: 'Only 5 units available in stock',
                    error: 'Bad Request',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'Item not found in buyer cart',
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
                "Deletes a specific item from the buyer's cart. Removes supplier grouping if no items remain for that supplier.",
        }),
        ApiParam({ name: 'itemId', type: Number, description: 'Cart Item ID' }),
        ApiOkResponse({
            description: 'Item removed successfully',
            type: CartResponseDto,
        }),
        ApiNotFoundResponse({
            description: 'Item or cart not found',
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
                "Marks the buyer's cart as deleted. Once deleted, it cannot be retrieved as active.",
        }),
        ApiOkResponse({
            description: 'Cart deleted successfully',
            schema: {
                example: { message: 'Cart deleted successfully' },
            },
        }),
        ApiNotFoundResponse({
            description: 'Active cart not found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'No active cart found for this buyer',
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
                'Removes all items from a specific supplier in the cart. Deletes the cart if it was the last supplier.',
        }),
        ApiParam({
            name: 'supplierId',
            type: String,
            description: 'Supplier ID',
        }),
        ApiOkResponse({
            description: 'Supplier removed successfully; updated cart returned',
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
                "Finalizes the buyer's cart by creating orders for each supplier. Marks the cart as bought and returns checkout details.",
        }),
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
                        },
                        {
                            id: 'uuid-order-2',
                            supplierId: 'uuid-supplier-id-2',
                            finalPrice: 100,
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
                    message: 'No active cart found for this buyer',
                    error: 'Not Found',
                },
            },
        }),
    );
}
