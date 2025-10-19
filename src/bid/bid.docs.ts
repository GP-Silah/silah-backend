import { applyDecorators } from '@nestjs/common';
import {
    ApiOperation,
    ApiResponse,
    ApiParam,
    ApiBadRequestResponse,
    ApiNotFoundResponse,
    ApiBody,
} from '@nestjs/swagger';
import { BidResponseDto } from './dtos/bidResponse.dto';
import { CreateBidDto } from './dtos/createBid.dto';

export function ApiDocsGetAllBids() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get all bids',
            description: `
Fetches a list of all available bids in the system.  
This endpoint is public and can be used by suppliers to browse open bids.  
Each bid includes its buyer information (buyer profile, user data, and card if available).
            `,
        }),
        ApiResponse({
            status: 200,
            description: 'List of all bids in the system.',
            type: [BidResponseDto],
        }),
    );
}

export function ApiDocsGetBidById() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get a bid by ID',
            description: `
Fetch a single bid by its unique identifier.  
Returns detailed information about the bid and its buyer.
            `,
        }),
        ApiParam({
            name: 'id',
            required: true,
            description: 'Bid ID to retrieve.',
            example: '123e4567-e89b-12d3-a456-426614174000',
        }),
        ApiResponse({
            status: 200,
            description: 'Bid details retrieved successfully.',
            type: BidResponseDto,
        }),
        ApiNotFoundResponse({
            description: 'Bid not found.',
            schema: {
                example: {
                    statusCode: 404,
                    message:
                        'Bid with ID 123e4567-e89b-12d3-a456-426614174000 not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsGetMyBids() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get my created bids (Buyer only)',
            description: `
Fetches all bids created by the authenticated **Buyer**.  
The bids are sorted by creation date (latest first).  
Each bid includes its buyer information.
            `,
        }),
        ApiResponse({
            status: 200,
            description: 'List of bids created by the authenticated buyer.',
            type: [BidResponseDto],
        }),
        ApiBadRequestResponse({
            description: 'Buyer not found or invalid request.',
            schema: {
                example: {
                    statusCode: 400,
                    message: 'Buyer not found',
                    error: 'Bad Request',
                },
            },
        }),
    );
}

export function ApiDocsCreateBid() {
    return applyDecorators(
        ApiOperation({
            summary: 'Create a new bid (Buyer only)',
            description: `
Allows a **Buyer** to create a new bid.  
The bid will include essential details such as name, main activity, submission deadline, and expected response time.<br><br>
Automatically associates the bid with the buyer creating it.
            `,
        }),
        ApiBody({
            type: CreateBidDto,
            description: 'Payload for creating a new bid.',
        }),
        ApiResponse({
            status: 201,
            description: 'Bid created successfully.',
            type: BidResponseDto,
        }),
        ApiBadRequestResponse({
            description: 'Invalid input or buyer not found.',
            schema: {
                oneOf: [
                    {
                        example: {
                            statusCode: 400,
                            message: 'Buyer not found',
                            error: 'Bad Request',
                        },
                    },
                    {
                        example: {
                            statusCode: 400,
                            message:
                                'Invalid date format for submissionDeadline',
                            error: 'Bad Request',
                        },
                    },
                ],
            },
        }),
    );
}

export function ApiDocsGetBidsIJoined() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get bids I joined (Supplier only)',
            description: `
Fetches all bids that the authenticated **Supplier** has joined through offers.<br>
Useful for suppliers who want to view only the bids they've participated in.<br><br>
Each bid includes detailed buyer information.
            `,
        }),
        ApiResponse({
            status: 200,
            description: 'List of bids that the supplier has joined.',
            type: [BidResponseDto],
        }),
        ApiNotFoundResponse({
            description: 'Supplier not found or no joined bids.',
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
