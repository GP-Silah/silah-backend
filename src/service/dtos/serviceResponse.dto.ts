import {
    ApiProperty,
    ApiPropertyOptional,
    getSchemaPath,
} from '@nestjs/swagger';
import { SupplierResponseDto } from 'src/supplier/dtos/supplierResponse.dto';
import { ServiceAvailability } from '@prisma/client';
import { InactiveSupplierResponseDto } from 'src/supplier/dtos/inactiveSupplierResponse.dto';

export class ServiceResponseDto {
    @ApiProperty({ description: 'Service ID', example: 'uuid-1234' })
    serviceId: string;

    @ApiPropertyOptional({
        description: 'Supplier ID (null = supplier deleted his account)',
        example: 'uuid-5678',
    })
    supplierId?: string | null;

    @ApiPropertyOptional({
        description:
            'Supplier details (null if the supplier deleted their account)',
        oneOf: [
            { $ref: getSchemaPath(SupplierResponseDto) },
            { $ref: getSchemaPath(InactiveSupplierResponseDto) },
        ],
        nullable: true,
    })
    supplier?: SupplierResponseDto | InactiveSupplierResponseDto | null;

    @ApiProperty({ description: 'Service name', example: 'Home Cleaning' })
    name: string;

    @ApiProperty({
        description: 'Service description',
        example: 'Professional deep cleaning service for apartments and houses',
    })
    description: string;

    @ApiProperty({ description: 'Price', example: 150.0 })
    price: number;

    @ApiProperty({
        description: 'Indicates if the price is negotiable',
        example: true,
    })
    isPriceNegotiable: boolean;

    @ApiProperty({ description: 'Category info' })
    category: { id: number; name: string };

    @ApiProperty({
        description: 'Service images filenames',
        type: [String],
        example: ['cleaning1.jpg', 'cleaning2.jpg'],
    })
    imagesFilesNames: string[];

    @ApiProperty({
        example: [
            'https://gp-silah.d025be9440ae5eb8295c69a36497276a.r2.cloudflarestorage.com/gp-silah/service1.jpeg?...',
        ],
        description:
            'Signed URLs from R2. Signed URLs expire 1 hour after creation.',
        format: 'uri',
        type: [String],
    })
    imagesFilesUrls: string[];

    @ApiProperty({
        description: 'Availability details of the service',
        example: 'WEEKENDS',
        enum: ServiceAvailability,
    })
    serviceAvailability: ServiceAvailability;

    @ApiProperty({ description: 'Publish status', example: true })
    isPublished: boolean;

    @ApiProperty({
        description: 'Wishlist count (only shown if supplier has PREMIUM plan)',
        example: 10,
        required: false,
    })
    wishlistCount?: number;

    @ApiProperty({ description: 'Average rating', example: 4.8 })
    avgRating: number;

    @ApiProperty({ description: 'Ratings count', example: 25 })
    ratingsCount: number;

    @ApiProperty({ description: 'Creation timestamp' })
    createdAt: Date;

    @ApiProperty({ description: 'Last update timestamp' })
    updatedAt: Date;

    @ApiProperty({
        description: 'Indicates if the service is soft-deleted',
        example: false,
    })
    isDeleted: boolean;

    @ApiProperty({
        description:
            'Timestamp when the service was soft-deleted (null if not deleted)',
        nullable: true,
    })
    deletedAt?: Date | null;
}
