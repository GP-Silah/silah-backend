import { StoreStatus } from '@prisma/client';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
    IsEnum,
    IsOptional,
    IsString,
    IsNumber,
    IsArray,
    Min,
} from 'class-validator';

export class UpdateSupplierDto {
    @ApiProperty({
        enum: StoreStatus,
        description: 'Current status of the supplier store',
        example: StoreStatus.OPEN,
    })
    @IsOptional()
    @IsEnum(StoreStatus, {
        message: 'storeStatus must be either OPEN or CLOSED',
    })
    storeStatus?: StoreStatus;

    @ApiPropertyOptional({
        description: 'Custom message displayed when the store is closed',
        example: 'We are closed for Eid holidays.',
    })
    @IsOptional()
    @IsString()
    storeClosedMsg?: string;

    @ApiPropertyOptional({
        description: 'Short bio or description of the store',
        example: 'We specialize in handmade bakery items.',
    })
    @IsOptional()
    @IsString()
    storeBio?: string;

    @ApiPropertyOptional({
        description: 'Delivery fees charged by the supplier',
        example: 15.5,
    })
    @IsOptional()
    @IsNumber()
    @Min(0, { message: 'deliveryFees cannot be negative' })
    deliveryFees?: number;
}
