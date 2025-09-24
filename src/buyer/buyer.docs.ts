import { applyDecorators } from '@nestjs/common';
import {
    ApiOperation,
    ApiOkResponse,
    ApiNotFoundResponse,
    ApiBadRequestResponse,
    ApiUnauthorizedResponse,
    ApiBearerAuth,
    ApiBody,
} from '@nestjs/swagger';
import { BuyerResponseDto } from './dtos/buyerResponse.dto';
import { CardDetailsDto } from './dtos/cardDetails.dto';
import { CreateCardDto } from './dtos/createCard.dto';

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
