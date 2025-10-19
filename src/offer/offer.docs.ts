import { applyDecorators } from '@nestjs/common';
import {
    ApiOperation,
    ApiOkResponse,
    ApiCreatedResponse,
    ApiNotFoundResponse,
    ApiBadRequestResponse,
    ApiForbiddenResponse,
    ApiParam,
    ApiQuery,
    ApiBody,
} from '@nestjs/swagger';
import { OfferResponseDto } from './dtos/offerResponse.dto';
import { CreateOfferDto } from './dtos/createOffer.dto';
import { OfferStatus } from '@prisma/client';

/**
 * @description Retrieve offer details by offer ID (public or protected depending on route usage).
 */
export function ApiDocsGetOfferById() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get offer details by ID',
            description: `
Retrieves detailed information about a specific offer, including:
<ul>
  <li>Offer details and pricing</li>
  <li>Linked supplier and bid information</li>
</ul>`,
        }),
        ApiParam({
            name: 'id',
            description: 'Unique identifier of the offer',
            example: 'ofr_12345',
        }),
        ApiOkResponse({
            description: 'Offer found and returned successfully.',
            type: OfferResponseDto,
        }),
        ApiNotFoundResponse({
            description: 'Offer not found.',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Offer not found for this ID.',
                    error: 'Not Found',
                },
            },
        }),
    );
}

/**
 * @description Get all offers for a given bid (buyer-only).
 */
export function ApiDocsGetOffersForBid() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get all offers for a bid (Buyer only)',
            description: `
Retrieves all submitted offers for a specific bid after the submission deadline.<br>
Only the <b>bid owner (buyer)</b> is authorized to access these offers.`,
        }),
        ApiParam({
            name: 'id',
            description: 'Unique identifier of the bid',
            example: 'bid_12345',
        }),
        ApiOkResponse({
            description: 'Successfully retrieved all offers for this bid.',
            type: [OfferResponseDto],
        }),
        ApiNotFoundResponse({
            description: 'Buyer or Bid not found.',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'No buyer or bid found for this ID and user.',
                    error: 'Not Found',
                },
            },
        }),
        ApiForbiddenResponse({
            description:
                'Unauthorized access: this bid does not belong to you.',
            schema: {
                example: {
                    statusCode: 403,
                    message:
                        'You are not authorized to view offers for this bid.',
                    error: 'Forbidden',
                },
            },
        }),
        ApiBadRequestResponse({
            description: 'Cannot view offers before submission deadline.',
            schema: {
                example: {
                    statusCode: 400,
                    message:
                        "You can't view the offers before the submission deadline arrives",
                    error: 'Bad Request',
                },
            },
        }),
    );
}

/**
 * @description Create a new offer for a bid (supplier-only).
 */
export function ApiDocsCreateOffer() {
    return applyDecorators(
        ApiOperation({
            summary: 'Create new offer for a bid (Supplier only)',
            description: `
Allows a <b>supplier</b> to create and submit a new offer for a specific bid.<br>
Automatically generates a pre-invoice and notifies the buyer.`,
        }),
        ApiParam({
            name: 'id',
            description: 'Unique identifier of the bid',
            example: 'bid_12345',
        }),
        ApiBody({ type: CreateOfferDto }),
        ApiCreatedResponse({
            description: 'Offer successfully created.',
            type: OfferResponseDto,
        }),
        ApiBadRequestResponse({
            description: 'Invalid data or supplier already submitted an offer.',
            schema: {
                example: {
                    statusCode: 400,
                    message: 'You have already submitted an offer for this bid',
                    error: 'Bad Request',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'Supplier or Bid not found.',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Supplier or bid not found for this ID and user',
                    error: 'Not Found',
                },
            },
        }),
    );
}

/**
 * @description Update the status of an offer (buyer-only).
 */
export function ApiDocsUpdateOfferStatus() {
    return applyDecorators(
        ApiOperation({
            summary: 'Update offer status (Buyer only)',
            description: `
Allows a <b>buyer</b> to accept or decline an offer.<br>
- If accepted → system automatically generates an invoice.<br>
- If declined → pre-invoice is marked as failed.`,
        }),
        ApiParam({
            name: 'id',
            description: 'Unique identifier of the offer',
            example: 'ofr_12345',
        }),
        ApiQuery({
            name: 'status',
            description: `New status to apply for the offer.`,
            enum: OfferStatus,
            example: OfferStatus.ACCEPTED,
        }),
        ApiOkResponse({
            description: 'Offer status successfully updated.',
            type: OfferResponseDto,
        }),
        ApiBadRequestResponse({
            description: 'Invalid status or offer cannot be updated.',
            schema: {
                example: {
                    statusCode: 400,
                    message: 'Only offers with pending status can be updated',
                    error: 'Bad Request',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'Buyer or Offer not found.',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Buyer or offer not found for this ID and user',
                    error: 'Not Found',
                },
            },
        }),
        ApiForbiddenResponse({
            description: 'You are not authorized to update this offer.',
            schema: {
                example: {
                    statusCode: 403,
                    message:
                        'You are not authorized to modify offers for this bid',
                    error: 'Forbidden',
                },
            },
        }),
    );
}
