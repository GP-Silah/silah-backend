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
import { CreateCardStep1Dto, CreateCardStep2Dto } from './dtos/createCard.dto';
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

export function ApiDocsSaveOrReplaceCurrentBuyerCardStep1() {
    return applyDecorators(
        ApiOperation({
            summary: 'Initiate card save or replacement for buyer',
            description:
                `**Step 1 of the two-step flow to save a buyer card using Tap:**<br><br>` +
                `This endpoint creates a temporary charge and redirects the user to complete 3D Secure verification (OTP). ` +
                `If the buyer already has a card, it will be deleted from Tap and replaced with the new one. ` +
                `The response includes a \`chargeId\` and a \`transactionUrl\` which must be stored by the frontend to complete Step 2.<br><br>` +
                `⚠️ **Important:** When testing, always use Tap's [test card values](https://developers.tap.company/reference/testing-cards). ` +
                `Live cards should only be used in production.<br><br>` +
                `Step 1 must be followed by Step 2 (\`PUT /api/buyers/me/card/confirm\`) to verify the charge and save the card information in the database.`,
        }),
        ApiBearerAuth(),
        ApiBody({
            description:
                'Card details provided from Tap tokenization (tokenId and redirect URL)',
            type: CreateCardStep1Dto,
        }),
        ApiOkResponse({
            description:
                'Charge created successfully, redirect user to complete 3D Secure',
            schema: {
                example: {
                    transactionUrl: 'https://secure.tap.company/checkout/...',
                    chargeId: 'chg_TS05A0820250903Ma230110749',
                },
            },
        }),
        ApiBadRequestResponse({
            description: 'Invalid Tap token or input data',
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

export function ApiDocsSaveOrReplaceCurrentBuyerCardStep2() {
    return applyDecorators(
        ApiOperation({
            summary: 'Confirm and save buyer card after Tap redirect',
            description:
                `**Two-step flow for saving a buyer card using Tap:**<br><br>` +
                `**Step 1:** Call the \`PUT /api/buyers/me/card\` endpoint with a Tap token and redirect URL. ` +
                `This creates a temporary charge and redirects the user to complete 3D Secure verification (OTP). ` +
                `The response contains a \`chargeId\` which must be kept for step 2.<br><br>` +
                `**Step 2:** After the user completes the 3D Secure step, Tap redirects back to your frontend \`redirect_url\` with \`tap_id\` (chargeId). ` +
                `Your frontend then calls this endpoint (\`PUT /api/buyers/me/card/confirm\`) with that \`chargeId\`. ` +
                `The backend will verify the charge status and extract the saved card details directly from the charge object. ` +
                `The card information is then stored in the database for future charges.<br><br>` +
                `⚠️ **Important:** When testing, make sure to use Tap's [test card values](https://developers.tap.company/reference/testing-cards) for generating tokens and performing charges. ` +
                `Live cards should only be used in production.<br><br>` +
                `These two endpoints are connected: step 1 initiates the card save and step 2 completes it.`,
        }),
        ApiBearerAuth(),
        ApiBody({
            description: 'Charge ID returned from Tap after 3D Secure redirect',
            type: CreateCardStep2Dto,
        }),
        ApiOkResponse({
            description: 'Card saved successfully',
            schema: {
                example: {
                    message: 'Card saved successfully',
                    card: {
                        id: 'f1a2b3c4-d5e6-7890-ab12-34567890cdef',
                        tapCardId: 'card_TS35A62593XRcF16R9F720',
                        cardHolderName: 'TESTER FIVE',
                        last4: '1019',
                        brand: 'VISA',
                        expMonth: 1,
                        expYear: 2039,
                    },
                },
            },
        }),
        ApiBadRequestResponse({
            description: 'Charge not successful or no card found',
            schema: {
                example: {
                    statusCode: 400,
                    message:
                        'No card information found in the charge. Maybe payment failed or method is not a card.',
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
