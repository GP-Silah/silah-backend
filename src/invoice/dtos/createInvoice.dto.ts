import { ApiProperty } from '@nestjs/swagger';
import {
    IsString,
    IsOptional,
    IsNumber,
    IsDateString,
    IsEnum,
    ValidateNested,
    IsArray,
    ArrayMinSize,
    ValidatorConstraint,
    ValidatorConstraintInterface,
    ValidationArguments,
    Validate,
    ValidationOptions,
    registerDecorator,
    ValidateIf,
} from 'class-validator';
import { Type } from 'class-transformer';
import { InvoiceTermsOfPayment } from '@prisma/client';

@ValidatorConstraint({ name: 'EitherProductOrService', async: false })
export class EitherProductOrServiceConstraint
    implements ValidatorConstraintInterface
{
    validate(_: any, args: ValidationArguments) {
        const obj = args.object as any;
        const hasProduct = !!obj.relatedProductId;
        const hasService = !!obj.relatedServiceId;

        // Exactly one must exist
        return (hasProduct || hasService) && !(hasProduct && hasService);
    }

    defaultMessage() {
        return 'Each invoice item must reference either a product or a service, not both.';
    }
}

export function IsFutureDate(validationOptions?: ValidationOptions) {
    return function (object: Object, propertyName: string) {
        registerDecorator({
            name: 'isFutureDate',
            target: object.constructor,
            propertyName,
            options: validationOptions,
            validator: {
                validate(value: any, args: ValidationArguments) {
                    const date = new Date(value);
                    const now = new Date();
                    return date > now; // must be strictly in the future
                },
                defaultMessage(args: ValidationArguments) {
                    return `${args.property} must be a future date`;
                },
            },
        });
    };
}

export class CreateInvoiceItemDto {
    @ApiProperty({
        description: 'Display name of the invoiced product or service.',
        example: 'Premium Wooden Chair',
    })
    @IsString()
    name: string;

    @ApiProperty({
        description: 'Short description of the item.',
        example: 'High-quality oak wood with natural finish.',
    })
    @IsString()
    description: string;

    @ApiProperty({
        description: 'Details agreed between buyer and supplier.',
        example: 'Includes free delivery and 2-year warranty.',
    })
    @IsString()
    agreedDetails: string;

    @ApiProperty({
        description:
            'Quantity of the product purchased (if service then they should write 1).',
        example: 5,
    })
    @IsNumber()
    quantity: number;

    @ApiProperty({
        description: 'Unit price of the item.',
        example: 99.99,
    })
    @IsNumber()
    unitPrice: number;

    @ApiProperty({
        description: 'Service ID if this item represents a service.',
        required: false,
    })
    @IsOptional()
    @IsString()
    relatedServiceId?: string;

    @ApiProperty({
        description: 'Product ID if this item represents a product.',
        required: false,
    })
    @IsOptional()
    @IsString()
    relatedProductId?: string;

    @Validate(EitherProductOrServiceConstraint)
    validateEitherProductOrService: boolean;
}

export class CreateInvoiceDto {
    @ApiProperty({
        description: 'Identifier of the buyer who will receive this invoice.',
    })
    @IsString()
    buyerId: string;

    @ApiProperty({
        description: 'Identifier of the supplier issuing this invoice.',
    })
    @IsString()
    supplierId: string;

    @ApiProperty({
        description: 'Expected delivery date for the invoice items.',
        example: '2025-10-08',
    })
    @IsDateString()
    @IsFutureDate({ message: 'Delivery date must be in the future' })
    deliveryDate: string;

    @ApiProperty({
        description: 'Terms of payment for the invoice.',
        enum: InvoiceTermsOfPayment,
    })
    @IsEnum(InvoiceTermsOfPayment)
    termsOfPayment: InvoiceTermsOfPayment;

    @ApiProperty({
        description:
            'Upfront payment amount (required only when termsOfPayment = PARTIAL).',
        required: false,
    })
    @ValidateIf((o) => o.termsOfPayment === InvoiceTermsOfPayment.PARTIAL)
    @IsNumber()
    upfrontAmount?: number;

    @ApiProperty({
        description: 'Optional notes or terms added by the supplier.',
        required: false,
    })
    @IsOptional()
    @IsString()
    notesAndTerms?: string;

    @ApiProperty({
        description: 'List of items included in this invoice.',
        type: [CreateInvoiceItemDto],
    })
    @IsArray()
    @ArrayMinSize(1)
    @ValidateNested({ each: true })
    @Type(() => CreateInvoiceItemDto)
    items: CreateInvoiceItemDto[];
}
