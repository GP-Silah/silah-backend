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
        description: 'File name of the store banner image in R2 bucket',
        example: 'banner123-6963ac71-3e92-441d-badd-a57b4a99b2e5.png',
    })
    @IsOptional()
    @IsString()
    storeBannerFileName?: string;

    @ApiPropertyOptional({
        description:
            'Signed URL from R2. Signed URLs expire 1 hour after creation.',
        example: 'https://cdn.example.com/banners/banner123.png',
        format: 'uri',
    })
    @IsOptional()
    @IsString()
    storeBannerFileUrl?: string;

    @ApiPropertyOptional({
        description: 'Delivery fees charged by the supplier',
        example: 15.5,
    })
    @IsOptional()
    @IsNumber()
    @Min(0, { message: 'deliveryFees cannot be negative' })
    deliveryFees?: number;

    @ApiPropertyOptional({
        description:
            'List of favorite categories (only subcategories) for quick access',
        type: [Object],
        example: [
            { id: '16', name: 'Animal Feed' },
            { id: '33', name: 'Jewelry & Watches' },
        ],
    })
    @IsOptional()
    @IsArray()
    favoriteCategories?: { id: string; name: string }[];
}
