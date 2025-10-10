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
    IsUUID,
    ValidationOptions,
    registerDecorator,
    ValidationArguments,
    IsArray,
} from 'class-validator';

export function HasExactlyOneId(
    propertyOne: string,
    propertyTwo: string,
    validationOptions?: ValidationOptions,
) {
    return function (object: any, propertyName: string) {
        registerDecorator({
            name: 'HasExactlyOneId',
            target: object.constructor,
            propertyName,
            options: validationOptions,
            constraints: [propertyOne, propertyTwo],
            validator: {
                validate(_: any, args: ValidationArguments) {
                    const [p1, p2] = args.constraints;
                    const v1 = (args.object as any)[p1];
                    const v2 = (args.object as any)[p2];
                    return (!!v1 && !v2) || (!v1 && !!v2); // exactly one must exist
                },
                defaultMessage(args: ValidationArguments) {
                    const [p1, p2] = args.constraints;
                    return `Exactly one of "${p1}" or "${p2}" must be provided.`;
                },
            },
        });
    };
}

export function ValidateReviewStructure(validationOptions?: ValidationOptions) {
    return function (object: Object, propertyName?: string) {
        registerDecorator({
            name: 'ValidateReviewStructure',
            target: object.constructor,
            propertyName: propertyName || 'itemsReview',
            options: validationOptions,
            validator: {
                validate(_: any, args: ValidationArguments) {
                    const review = args.object as CreateReviewDto;

                    const isOrderReview = !!review.orderId;
                    const isInvoiceReview = !!review.invoiceId;

                    if (!Array.isArray(review.itemsReview)) return true;

                    for (const item of review.itemsReview as CreateItemReviewDto[]) {
                        if (isOrderReview) {
                            // For order-based reviews: each item must have orderItemId only
                            if (!item.orderItemId || item.invoiceItemId)
                                return false;
                        }

                        if (isInvoiceReview) {
                            // For invoice-based reviews: each item must have invoiceItemId only
                            if (!item.invoiceItemId || item.orderItemId)
                                return false;
                        }
                    }

                    return true;
                },
                defaultMessage(args: ValidationArguments) {
                    const review = args.object as CreateReviewDto;
                    if (review.orderId)
                        return 'Since this is an order-based review, each item must include only `orderItemId`.';
                    if (review.invoiceId)
                        return 'Since this is an invoice-based review, each item must include only `invoiceItemId`.';
                    return 'Invalid review structure.';
                },
            },
        });
    };
}

export class CreateItemReviewDto {
    @ApiPropertyOptional({
        description:
            "The cart item ID this review is linked to (if it's an order-based review). Should only be used when orderId is provided on parent review.",
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

HasExactlyOneId('orderId', 'invoiceId', {
    message: 'Exactly one of orderId or invoiceId must be provided.',
});
ValidateReviewStructure();
export class CreateReviewDto {
    @ApiPropertyOptional({
        description:
            'The order ID this review is related to (if order-based). Exactly one of `orderId` or `invoiceId` must be provided.',
        example: '3c90b93d-223f-4dfb-9d1c-0bbf2fae861b',
    })
    @IsOptional()
    @IsUUID()
    orderId?: string;

    @ApiPropertyOptional({
        description:
            'The invoice ID this review is related to (if invoice-based). Exactly one of `orderId` or `invoiceId` must be provided.',
        example: 'a1d83c33-7f8c-4f1d-b37e-9b6fbb9d6502',
    })
    @IsOptional()
    @IsUUID()
    invoiceId?: string;

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
