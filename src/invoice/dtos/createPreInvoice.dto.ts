import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsOptional, IsNumber } from 'class-validator';

//TODO: come back to this once the groups are done
export class CreatePreInvoiceDto {
    @ApiProperty({
        description:
            'Identifier of the group purchase that triggered this pre-invoice.',
    })
    @IsString()
    groupPurchaseId: string;

    @ApiProperty({
        description: 'Buyer associated with this pre-invoice.',
    })
    @IsString()
    buyerId: string;

    @ApiProperty({
        description: 'Supplier associated with this pre-invoice (if any).',
    })
    @IsString()
    supplierId: string;

    @ApiProperty({
        description: 'Product related to this pre-invoice.',
    })
    @IsString()
    productId: string;

    @ApiProperty({
        description: '(unit price x quantity) + supplier delivery fees.',
        example: 120.0,
    })
    @IsNumber()
    amount: number;
}
