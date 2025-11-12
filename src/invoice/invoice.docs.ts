import { applyDecorators } from '@nestjs/common';
import {
    ApiOperation,
    ApiQuery,
    ApiResponse,
    ApiBadRequestResponse,
    ApiNotFoundResponse,
    ApiParam,
    ApiBody,
    ApiForbiddenResponse,
    getSchemaPath,
} from '@nestjs/swagger';
import {
    InvoiceResponseDto,
    PreInvoiceResponseDto,
} from './dtos/invoiceResponse.dto';
import { CreateInvoiceDto } from './dtos/createInvoice.dto';
import { PayInvoiceDto } from './dtos/payInvoice.dto';

export function ApiDocsGetMyInvoices() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get my invoices and pre-invoices',
            description: `
Fetches all invoices and pre-invoices associated with the authenticated user.<br><br>
Optional query parameters allow filtering:<br>
<ul>
    <li><strong>status</strong> - filter by invoice or pre-invoice status:
        <ul>
            <li>InvoiceStatus: PENDING, ACCEPTED, REJECTED, PARTIALLY_PAID, FULLY_PAID</li>
            <li>PreInvoiceStatus: PENDING, SUCCESSFUL, FAILED</li>
        </ul>
    </li>
    <li><strong>showFor</strong> - filter by item type:
        <ul>
            <li><strong>products</strong> - invoices only</li>
            <li><strong>services</strong> - invoices only</li>
            <li><strong>bids</strong> - pre-invoices only</li>
            <li><strong>groups</strong> - pre-invoices only</li>
            <li><strong>all</strong> - both invoices and pre-invoices</li>
        </ul>
    </li>
</ul>
Invoices and pre-invoices are automatically sorted with the latest first.
`,
        }),
        ApiQuery({
            name: 'status',
            required: false,
            description:
                'Filter by status. Can be an InvoiceStatus or a PreInvoiceStatus. Note: PENDING exists in both types, others are exclusive.',
            example: 'PENDING',
        }),
        ApiQuery({
            name: 'showFor',
            required: false,
            description:
                "Filter invoices/pre-invoices by item type. Allowed values: 'all', 'products' (invoices only), 'services' (invoices only), 'bids' (pre-invoices only), 'groups' (pre-invoices only).",
            example: 'products',
        }),
        ApiResponse({
            status: 200,
            description:
                'List of invoices and pre-invoices for the authenticated user.',
            type: [InvoiceResponseDto],
        }),
        ApiBadRequestResponse({
            description: 'Invalid query parameters (status or showFor).',
            schema: {
                oneOf: [
                    {
                        example: {
                            statusCode: 400,
                            message: 'Invalid status: wrongStatus',
                            error: 'Bad Request',
                        },
                    },
                    {
                        example: {
                            statusCode: 400,
                            message: 'Invalid showFor choice: unknown',
                            error: 'Bad Request',
                        },
                    },
                    {
                        example: {
                            statusCode: 400,
                            message:
                                'Cannot filter invoices by "bids" showFor with status "ACCEPTED". Use a pre-invoice status instead.',
                            error: 'Bad Request',
                        },
                    },
                    {
                        example: {
                            statusCode: 400,
                            message:
                                'Cannot filter pre-invoices by "products" showFor with status "FAILED". Use an invoice status instead.',
                            error: 'Bad Request',
                        },
                    },
                ],
            },
        }),
    );
}

export function ApiDocsGetMyInvoiceById() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get a single invoice or pre-invoice by ID',
            description: `
Fetch a specific invoice or pre-invoice belonging to the authenticated user.<br><br>
The endpoint checks whether the invoice exists and whether it belongs to the current user.
`,
        }),
        ApiParam({
            name: 'id',
            required: true,
            description: 'Invoice or pre-invoice ID.',
            example: '123e4567-e89b-12d3-a456-426614174000',
        }),
        ApiResponse({
            status: 200,
            description: 'Invoice or pre-invoice details.',
            schema: {
                oneOf: [
                    { $ref: getSchemaPath(InvoiceResponseDto) },
                    { $ref: getSchemaPath(PreInvoiceResponseDto) },
                ],
            },
        }),
        ApiBadRequestResponse({
            description: 'Invalid request.',
            schema: {
                example: {
                    statusCode: 400,
                    message: 'Buyer account not found',
                    error: 'Bad Request',
                },
            },
        }),
        ApiNotFoundResponse({
            description:
                'Invoice or pre-invoice not found for this ID and user.',
            schema: {
                example: {
                    statusCode: 404,
                    message:
                        'No invoice or pre-invoice found for this ID and user.',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsCreateInvoice() {
    return applyDecorators(
        ApiOperation({
            summary: 'Create a new invoice',
            description: `
Creates an invoice for a buyer from the supplier. Validates buyer, supplier, and items.<br>
- Upfront amount must not exceed total or max allowed percentage (30%).<br>
- Items must reference exactly one of product or service.<br>
- Returns the created invoice with all items and calculated totals.
`,
        }),
        ApiBody({
            type: CreateInvoiceDto,
            description: 'Payload for creating a new invoice.',
        }),
        ApiResponse({
            status: 201,
            description: 'Invoice created successfully.',
            type: InvoiceResponseDto,
        }),
        ApiBadRequestResponse({
            description:
                'Invalid request, validation failed, or business rule violation.',
            schema: {
                oneOf: [
                    {
                        example: {
                            statusCode: 400,
                            message:
                                'Upfront amount cannot exceed total invoice amount.',
                            error: 'Bad Request',
                        },
                    },
                    {
                        example: {
                            statusCode: 400,
                            message:
                                'Each invoice item must reference either a product or a service, not both.',
                            error: 'Bad Request',
                        },
                    },
                ],
            },
        }),
    );
}

export function ApiDocsUpdateInvoiceStatus() {
    return applyDecorators(
        ApiOperation({
            summary: 'Update status of a pending invoice',
            description: `
Allows a buyer to update the status of a PENDING invoice to ACCEPTED or REJECTED.<br>
- Only PENDING invoices can be updated.<br>
- Role must be BUYER.
`,
        }),
        ApiParam({
            name: 'id',
            required: true,
            description: 'Invoice ID to update.',
            example: '123e4567-e89b-12d3-a456-426614174000',
        }),
        ApiQuery({
            name: 'status',
            required: true,
            description:
                'New status of the invoice. Allowed values: ACCEPTED, REJECTED.',
            example: 'ACCEPTED',
        }),
        ApiResponse({
            status: 200,
            description: 'Invoice status updated successfully.',
            type: InvoiceResponseDto,
        }),
        ApiBadRequestResponse({
            description: 'Invalid status or business rule violation.',
            schema: {
                example: {
                    statusCode: 400,
                    message:
                        'Invalid status. Allowed values: ACCEPTED, REJECTED',
                    error: 'Bad Request',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'Invoice not found for this buyer.',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Invoice not found for this buyer',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsPayInvoice() {
    return applyDecorators(
        ApiOperation({
            summary: 'Pay an invoice',
            description: `
Allows a buyer to pay an accepted or partially paid invoice using a saved card in Tap Payments.<br>
- Partial payments supported for upfront amounts.<br>
- Returns payment summary and Tap charge ID.<br>
- May return a redirect URL for 3DS authentication if required.
`,
        }),
        ApiParam({
            name: 'id',
            required: true,
            description: 'Invoice ID to pay.',
            example: '123e4567-e89b-12d3-a456-426614174000',
        }),
        ApiBody({
            description:
                'Optional existing charge ID if already created, if not provide the redirectUrl that Tap will redirect the user back to after authentication.',
            type: PayInvoiceDto,
        }),
        ApiResponse({
            status: 200,
            description:
                'Payment successful or redirect required for 3DS authentication.',
            schema: {
                example: {
                    message: 'Invoice paid successfully',
                    tapChargeId: 'chg_abc123',
                    buyerId: 'buyerId123',
                    invoiceId: '123e4567-e89b-12d3-a456-426614174000',
                    totalPaid: 1000,
                    totalAmount: 1000,
                },
            },
        }),
        ApiBadRequestResponse({
            description:
                'Payment failed, invalid invoice state, or validation error.',
            schema: {
                oneOf: [
                    {
                        example: {
                            statusCode: 400,
                            message: 'Invoice already paid',
                            error: 'Bad Request',
                        },
                    },
                    {
                        example: {
                            statusCode: 400,
                            message: 'No saved card found for this buyer',
                            error: 'Bad Request',
                        },
                    },
                ],
            },
        }),
        ApiForbiddenResponse({
            description:
                'Buyer cannot pay an invoice that does not belong to them.',
            schema: {
                example: {
                    statusCode: 403,
                    message: 'You are not allowed to pay this invoice',
                    error: 'Forbidden',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'Invoice not found.',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Invoice not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}
