import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import {
    IsInt,
    IsOptional,
    Max,
    Min,
    IsString,
    Length,
    ValidateNested,
    IsArray,
} from 'class-validator';

export class CreateItemReviewDto {
    @ApiPropertyOptional({
        description:
            "The order item ID this review is linked to (if it's an order-based review). Should only be used when orderId is provided on parent review.",
        example: 12,
    })
    @IsOptional()
    @IsInt()
    orderItemId?: number;

    @ApiPropertyOptional({
        description:
            "The invoice item ID this review is linked to (if it's an invoice-based review). Should only be used when invoiceId is provided on parent review.",
        example: 34,
    })
    @IsOptional()
    @IsInt()
    invoiceItemId?: number;

    @ApiProperty({
        description: 'Rating for this item (1-5)',
        example: 5,
        default: 5,
        minimum: 1,
        maximum: 5,
    })
    @IsInt()
    @Min(1)
    @Max(5)
    itemRating: number = 5;

    @ApiPropertyOptional({
        description:
            'Optional written feedback for the reviewed item (max 150 chars)',
        example: 'The product quality was excellent and packaging was neat!',
        maxLength: 150,
    })
    @IsOptional()
    @IsString()
    @Length(1, 150)
    writtenReviewOfItem?: string;
}

export class CreateReviewDto {
    @ApiProperty({
        description: 'Supplier rating (1-5)',
        example: 5,
        default: 5,
        minimum: 1,
        maximum: 5,
    })
    @IsInt()
    @Min(1)
    @Max(5)
    supplierRating: number = 5;

    @ApiPropertyOptional({
        description:
            'Optional written feedback for the supplier (max 150 chars)',
        example: 'Excellent communication and fast delivery.',
        maxLength: 150,
    })
    @IsOptional()
    @IsString()
    @Length(1, 150)
    writtenReviewOfSupplier?: string;

    @ApiProperty({
        description:
            'Array of item reviews for each item in this order/invoice',
        type: [CreateItemReviewDto],
    })
    @IsArray()
    @ValidateNested({ each: true })
    @Type(() => CreateItemReviewDto)
    itemsReview: CreateItemReviewDto[];
}
