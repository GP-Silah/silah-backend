import { applyDecorators } from '@nestjs/common';
import {
    ApiOperation,
    ApiOkResponse,
    ApiNotFoundResponse,
    ApiBadRequestResponse,
    ApiBearerAuth,
    ApiBody,
    ApiParam,
} from '@nestjs/swagger';
import { BuyerResponseDto } from './dtos/buyerResponse.dto';
import { CardDetailsDto } from './dtos/cardDetails.dto';
import { CreateCardDto } from './dtos/createCard.dto';
import { WishlistItemResponseDto } from './dtos/wishlistItemResponse.dto';
import { ProductResponseDto } from 'src/product/dtos/productResponse.dto';

export function ApiDocsGetCurrentBuyerData() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get current buyer data',
            description:
                "Returns the currently authenticated buyer's user details and saved card information (if available).",
        }),
        ApiBearerAuth(),
        ApiOkResponse({
            description: 'Current buyer data retrieved successfully',
            type: BuyerResponseDto,
        }),
        ApiNotFoundResponse({
            description: 'Buyer not found',
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

export function ApiDocsGetCurrentBuyerCard() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get current buyer card',
            description:
                "Returns the saved card of the currently authenticated buyer. If the buyer has no card, returns `{ message: 'No card found', card: null }`.",
        }),
        ApiBearerAuth(),
        ApiOkResponse({
            description: 'Buyer card retrieved successfully',
            type: CardDetailsDto,
        }),
        ApiNotFoundResponse({
            description: 'No card found',
            schema: {
                example: {
                    message: 'No card found',
                    card: null,
                },
            },
        }),
    );
}

export function ApiDocsSaveOrReplaceCurrentBuyerCard() {
    return applyDecorators(
        ApiOperation({
            summary: 'Save or replace current buyer card',
            description:
                "Creates or replaces the authenticated buyer's card using Tap tokenization.<br>" +
                'If a card already exists, it will be deleted from Tap and replaced with the new one.',
        }),
        ApiBearerAuth(),
        ApiBody({
            description: 'Card details provided from Tap tokenization',
            type: CreateCardDto,
        }),
        ApiOkResponse({
            description: 'Card saved successfully',
            schema: {
                example: {
                    message: 'Card saved successfully',
                    card: {
                        id: 'f1a2b3c4-d5e6-7890-ab12-34567890cdef',
                        tapCardId: 'card_abc123xyz',
                        cardHolderName: 'Norah Alqahtani',
                        last4: '4242',
                        brand: 'Visa',
                        expMonth: 12,
                        expYear: 2028,
                    },
                },
            },
        }),
        ApiBadRequestResponse({
            description: 'Invalid input data',
            schema: {
                example: {
                    statusCode: 400,
                    message: 'Invalid Tap token',
                    error: 'Bad Request',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'User not found',
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

export function ApiDocsDeleteCurrentBuyerCard() {
    return applyDecorators(
        ApiOperation({
            summary: 'Delete current buyer card',
            description:
                "Deletes the authenticated buyer's saved card from Tap and the database.",
        }),
        ApiBearerAuth(),
        ApiOkResponse({
            description: 'Card deleted successfully',
            schema: {
                example: {
                    message: 'Card deleted successfully',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'No card found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'No card found for this buyer',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsGetCurrentBuyerWishlist() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get current buyer wishlist',
            description:
                'Returns the wishlist items of the currently authenticated buyer. Each item can be a product or a service.',
        }),
        ApiBearerAuth(),
        ApiOkResponse({
            description: 'Wishlist retrieved successfully',
            type: [WishlistItemResponseDto],
        }),
        ApiNotFoundResponse({
            description: 'Buyer not found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Buyer not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsToggleWishlistItem() {
    return applyDecorators(
        ApiOperation({
            summary: 'Toggle an item in the buyer wishlist',
            description:
                'Adds the item to the wishlist if it is not already there, or removes it if it exists. Returns the updated wishlist.',
        }),
        ApiBearerAuth(),
        ApiParam({
            name: 'itemId',
            description: 'The ID of the product or service to toggle',
            required: true,
            type: 'string',
        }),
        ApiOkResponse({
            description: 'Item successfully added or removed from wishlist',
            schema: {
                example: {
                    message: 'Item added to wishlist',
                    isAdded: true,
                    updatedWishlist: [
                        {
                            itemId: '1234567890ab-cdef-1234-5678-abcdef123456',
                            itemType: 'PRODUCT',
                            // Note: Swagger cannot display the full DTO here
                            // The actual response will include the complete ProductResponseDto
                            product: 'See ProductResponseDto',
                        },
                        {
                            itemId: '1234567890ab-cdef-1234-5678-abcdef654321',
                            itemType: 'SERVICE',
                            // Note: Swagger cannot display the full DTO here
                            // The actual response will include the complete ServiceResponseDto
                            service: 'See ServiceResponseDto',
                        },
                    ],
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'Buyer or item not found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Item not found',
                    error: 'Not Found',
                },
            },
        }),
        ApiBadRequestResponse({
            description: 'Invalid itemId',
            schema: {
                example: {
                    statusCode: 400,
                    message: 'Invalid item ID format',
                    error: 'Bad Request',
                },
            },
        }),
    );
}
