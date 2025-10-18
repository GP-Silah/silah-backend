import { ApiProperty } from '@nestjs/swagger';
import {
    InvoiceStatus,
    InvoiceTermsOfPayment,
    PreInvoiceStatus,
} from '@prisma/client';
import { BuyerResponseDto } from 'src/buyer/dtos/buyerResponse.dto';
import { GroupPurchaseBuyerResponseDto } from 'src/group-purchase/dtos/groupPurchaseResponse.dto';
import { OfferResponseDto } from 'src/offer/dtos/offerResponse.dto';
import { ProductResponseDto } from 'src/product/dtos/productResponse.dto';
import { ServiceResponseDto } from 'src/service/dtos/serviceResponse.dto';
import { SupplierResponseDto } from 'src/supplier/dtos/supplierResponse.dto';

export class InvoiceItemResponseDto {
    @ApiProperty({
        description: 'Unique identifier of the invoice item.',
        example: 1,
    })
    invoiceItemId: number;

    @ApiProperty({
        description: 'Display name of the invoiced product or service.',
        example: 'Custom Website Design',
    })
    name: string;

    @ApiProperty({
        description: 'Short description of the item.',
        example: 'A modern business website with 5 pages.',
    })
    description: string;

    @ApiProperty({
        description: 'Details agreed between buyer and supplier for this item.',
        example: 'Includes SEO optimization and contact form integration.',
    })
    agreedDetails: string;

    @ApiProperty({
        description:
            'Quantity of the product purchased (if service then write 1).',
        example: 2,
    })
    quantity: number;

    @ApiProperty({
        description: 'Unit price of the product or service.',
        example: 500.0,
    })
    unitPrice: number;

    @ApiProperty({
        description: 'Total price for this line item (quantity x unit price).',
        example: 1000.0,
    })
    priceBasedQuantity: number;

    @ApiProperty({
        description:
            'Product details if this invoice item represents a product.',
        type: ProductResponseDto,
        required: false,
    })
    relatedProduct?: ProductResponseDto;

    @ApiProperty({
        description:
            'Service details if this invoice item represents a service.',
        type: ServiceResponseDto,
        required: false,
    })
    relatedService?: ServiceResponseDto;
}

export class PreInvoiceResponseDto {
    @ApiProperty({
        description: 'Unique identifier for the pre-invoice.',
        example: '23e4567-e89b-12d3-a456-426614174000',
    })
    preInvoiceId: string;

    @ApiProperty({
        description: 'Type identifier for frontend use.',
        enum: ['PRE_INVOICE'],
        example: 'PRE_INVOICE',
    })
    type: 'PRE_INVOICE';

    @ApiProperty({
        description: 'Status of the pre-invoice.',
        enum: PreInvoiceStatus,
        example: PreInvoiceStatus.PENDING,
    })
    status: PreInvoiceStatus;

    @ApiProperty({
        description:
            'Buyer who owns this pre-invoice (null if account is deleted).',
        type: BuyerResponseDto,
        required: false,
    })
    buyer?: BuyerResponseDto;

    @ApiProperty({
        description:
            'Supplier associated with this pre-invoice (null if account is deleted).',
        type: SupplierResponseDto,
        required: false,
    })
    supplier?: SupplierResponseDto;

    @ApiProperty({
        description:
            'Product associated with this pre-invoice (from group purchase).',
        type: ProductResponseDto,
        required: false,
    })
    product?: ProductResponseDto;

    @ApiProperty({
        description: 'The offer associated with this pre-invoice, if any.',
        type: OfferResponseDto,
        required: false,
    })
    offer?: OfferResponseDto;

    @ApiProperty({
        description:
            'The group purchase buyer relation for this pre-invoice, if any.',
        type: GroupPurchaseBuyerResponseDto,
        required: false,
    })
    groupPurchaseBuyer?: GroupPurchaseBuyerResponseDto;

    @ApiProperty({
        description: '(unit price x quantity) + supplier delivery fees.',
        example: 250.5,
    })
    amount: number;

    @ApiProperty({
        description: 'Creation timestamp of the pre-invoice.',
        example: '2025-10-07T09:00:00Z',
    })
    createdAt: Date;
}

export class InvoiceResponseDto {
    @ApiProperty({
        description: 'Unique identifier for the invoice.',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    invoiceId: string;

    @ApiProperty({
        description: 'Type identifier for frontend use.',
        enum: ['INVOICE'],
        example: 'INVOICE',
    })
    type: 'INVOICE';

    @ApiProperty({
        description: 'Current status of the invoice.',
        enum: InvoiceStatus,
        example: InvoiceStatus.PENDING,
    })
    status: InvoiceStatus;

    @ApiProperty({
        description:
            'Buyer associated with this invoice (null if his account is deleted).',
        type: BuyerResponseDto,
    })
    buyer?: BuyerResponseDto;

    @ApiProperty({
        description:
            'Supplier associated with this invoice (null if his account is deleted).',
        type: SupplierResponseDto,
    })
    supplier?: SupplierResponseDto;

    @ApiProperty({
        description: 'Payment terms applied to this invoice.',
        enum: InvoiceTermsOfPayment,
        example: InvoiceTermsOfPayment.PARTIAL,
    })
    termsOfPayment: InvoiceTermsOfPayment;

    @ApiProperty({
        description: 'Amount to be paid upfront (if applicable).',
        required: false,
        example: 100.0,
    })
    upfrontAmount?: number;

    @ApiProperty({
        description:
            'Tap Payments charge ID for the upfront payment (if applicable).',
        required: false,
        example: 'chg_abc123',
    })
    tapChargeIdForUpfront?: string;

    @ApiProperty({
        description: 'Tap Payments charge ID for the payment.',
        required: false,
        example: 'chg_abc123',
    })
    tapChargeId?: string;

    @ApiProperty({
        description: 'Scheduled delivery date for this invoice.',
        example: '2025-10-08',
    })
    deliveryDate: Date;

    @ApiProperty({
        description:
            'Additional notes or contractual terms provided by the supplier.',
        required: false,
    })
    notesAndTerms?: string;

    @ApiProperty({
        description: 'List of items included in this invoice.',
        type: [InvoiceItemResponseDto],
    })
    items: InvoiceItemResponseDto[];

    @ApiProperty({
        description: 'Pre-invoice that was upgraded to this invoice, if any.',
        type: PreInvoiceResponseDto,
        required: false,
    })
    preInvoice?: PreInvoiceResponseDto;

    @ApiProperty({
        description: 'Total amount for this invoice (sum of all items).',
        example: 1000.0,
    })
    amount: number;

    @ApiProperty({
        description: 'Creation timestamp of the invoice.',
        example: '2025-10-07T09:00:00Z',
    })
    createdAt: Date;
}
