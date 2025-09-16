import { StoreStatus, SupplierStatus } from '@prisma/client';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class StorefrontResponseDto {
    @ApiProperty({ description: 'Supplier unique ID', example: 'uuid-1234' })
    supplierId: string;

    @ApiProperty({ description: 'Supplier display name', example: 'John Doe' })
    supplierName: string;

    @ApiProperty({
        description: 'Business name of the user',
        example: 'John Bakery',
    })
    businessName: string;

    @ApiProperty({ description: 'City of the user', example: 'Riyadh' })
    city: string;

    @ApiProperty({
        enum: StoreStatus,
        description: 'Current store status',
        example: StoreStatus.OPEN,
    })
    storeStatus: StoreStatus;

    @ApiProperty({
        description: 'Message displayed if the store is closed',
        example: 'We are closed for Eid holidays.',
    })
    storeClosedMsg: string;

    @ApiPropertyOptional({
        description: 'Short bio or description of the store',
        example: 'We specialize in handmade bakery items.',
    })
    storeBio?: string;

    @ApiPropertyOptional({
        description: 'File name of the store banner image in R2 bucket',
        example: 'banner123-6963ac71-3e92-441d-badd-a57b4a99b2e5.png',
    })
    storeBannerFileName?: string;

    @ApiPropertyOptional({
        description:
            'Signed URL from R2. Signed URLs expire 1 hour after creation.',
        example: 'https://cdn.example.com/banners/banner123.png',
        format: 'uri',
    })
    storeBannerFileUrl?: string;

    @ApiProperty({
        description: 'Delivery fees charged by the supplier',
        example: 15.5,
    })
    deliveryFees: number;

    @ApiProperty({
        description: 'Average rating of the supplier',
        example: 4.5,
    })
    avgRating: number;

    @ApiProperty({ description: 'Number of ratings received', example: 23 })
    ratingsCount: number;

    @ApiProperty({
        enum: SupplierStatus,
        description: 'Current status of the supplier account',
        example: SupplierStatus.ACTIVE,
    })
    supplierStatus: SupplierStatus;
}
