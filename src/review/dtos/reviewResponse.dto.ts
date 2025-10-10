import {
    ApiProperty,
    ApiPropertyOptional,
    getSchemaPath,
} from '@nestjs/swagger';
import { BuyerResponseDto } from 'src/buyer/dtos/buyerResponse.dto';
import { CartItemResponseDto } from 'src/cart/dtos/cartResponse.dto';
import { InvoiceItemResponseDto } from 'src/invoice/dtos/invoiceResponse.dto';
import { InactiveSupplierResponseDto } from 'src/supplier/dtos/inactiveSupplierResponse.dto';
import { SupplierResponseDto } from 'src/supplier/dtos/supplierResponse.dto';

export class ItemReviewResponseDto {
    @ApiProperty({
        description: 'Unique ID of this item review',
        example: 'd1f2a3b4-5678-90ab-cdef-1234567890ab',
    })
    itemReviewId: string;

    @ApiProperty({
        description: 'ID of the parent review',
        example: 'f1e2d3c4-5678-90ab-cdef-1234567890ab',
    })
    reviewId: string;

    @ApiPropertyOptional({
        description:
            'Details of the order item being reviewed (if review is order-based)',
        type: () => CartItemResponseDto,
    })
    orderItemReview?: Partial<CartItemResponseDto>;

    @ApiPropertyOptional({
        description:
            'Details of the invoice item being reviewed (if review is invoice-based)',
        type: () => InvoiceItemResponseDto,
    })
    invoiceItemReview?: Partial<InvoiceItemResponseDto>;

    @ApiProperty({
        description: 'ID of the buyer who wrote this review',
        example: 'y1x2w3v4-5678-90ab-cdef-1234567890ab',
    })
    buyerId: string;

    @ApiProperty({
        description: 'Rating given for this item',
        example: 5,
    })
    itemRating: number;

    @ApiPropertyOptional({
        description: 'Written feedback for this item review',
        example: 'The product quality was excellent.',
    })
    writtenReviewOfItem?: string;

    @ApiProperty({
        description: 'Date when this review was created',
        example: '2025-10-10T12:34:56.789Z',
    })
    createdAt: Date;
}

export class ReviewResponseDto {
    @ApiProperty({
        description: 'Unique ID of the review',
        example: 'f1e2d3c4-5678-90ab-cdef-1234567890ab',
    })
    reviewId: string;

    @ApiPropertyOptional({
        description:
            'ID of the order this review is related to (if order-based)',
        example: '3c90b93d-223f-4dfb-9d1c-0bbf2fae861b',
    })
    orderId?: string;

    @ApiPropertyOptional({
        description:
            'ID of the invoice this review is related to (if invoice-based)',
        example: 'a1d83c33-7f8c-4f1d-b37e-9b6fbb9d6502',
    })
    invoiceId?: string;

    @ApiProperty({
        description: 'Details of the buyer who wrote the review',
        type: () => BuyerResponseDto,
    })
    buyer: BuyerResponseDto;

    @ApiProperty({
        description: 'Details of the supplier being reviewed',
        oneOf: [
            { $ref: getSchemaPath(SupplierResponseDto) },
            { $ref: getSchemaPath(InactiveSupplierResponseDto) },
        ],
    })
    supplier: SupplierResponseDto | InactiveSupplierResponseDto;

    @ApiProperty({
        description: 'Rating given to the supplier',
        example: 5,
    })
    supplierRating: number;

    @ApiPropertyOptional({
        description: 'Written feedback for the supplier',
        example: 'The supplier was very responsive and professional.',
    })
    writtenReviewOfSupplier?: string;

    @ApiProperty({
        description: 'List of item reviews under this review',
        type: () => [ItemReviewResponseDto],
    })
    itemsReview: ItemReviewResponseDto[];

    @ApiProperty({
        description: 'Date when this review was created',
        example: '2025-10-10T12:34:56.789Z',
    })
    createdAt: Date;
}
