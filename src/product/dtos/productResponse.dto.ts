import {
    ApiProperty,
    ApiPropertyOptional,
    getSchemaPath,
} from '@nestjs/swagger';
import { GroupPurchaseDeadline } from '@prisma/client';
import { InactiveSupplierResponseDto } from 'src/supplier/dtos/inactiveSupplierResponse.dto';
import { SupplierResponseDto } from 'src/supplier/dtos/supplierResponse.dto';

export class ProductResponseDto {
    @ApiProperty({ description: 'Product ID', example: 'uuid-1234' })
    productId: string;

    @ApiPropertyOptional({
        description: 'Supplier ID (null = supplier deleated his account)',
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

    @ApiProperty({
        description: 'Product name',
        example: 'Wireless Headphones',
    })
    name: string;

    @ApiProperty({
        description: 'Product description',
        example: 'Noise-cancelling over-ear headphones',
    })
    description: string;

    @ApiProperty({ description: 'Price', example: 199.99 })
    price: number;

    @ApiProperty({ description: 'Stock available', example: 50 })
    stock: number;

    @ApiProperty({ description: 'Category info' })
    category: { id: number; name: string };

    @ApiProperty({
        description: 'Product images filenames',
        type: [String],
        example: ['img1.jpg', 'img2.jpg'],
    })
    imagesFilesNames: string[];

    @ApiProperty({
        example: [
            'https://gp-silah.d025be9440ae5eb8295c69a36497276a.r2.cloudflarestorage.com/gp-silah/moon.jpeg-30510246-41f7-4cff-a052-78bcc30f7301.jpeg?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=...&X-Amz-Date=20250816T131236Z&X-Amz-Expires=3600&X-Amz-Signature=...',
        ],
        description:
            'Signed URLs from R2. Signed URLs expire 1 hour after creation.',
        format: 'uri',
        type: [String],
    })
    imagesFilesUrls: string[];

    @ApiProperty({ description: 'Case quantity', example: 1 })
    caseQuantity: number;

    @ApiProperty({ description: 'Minimum order quantity', example: 1 })
    minOrderQuantity: number;

    @ApiProperty({
        description: 'Maximum order quantity (null = unlimited)',
        nullable: true,
        example: 50,
    })
    maxOrderQuantity?: number | null;

    @ApiProperty({ description: 'Enable group purchase', example: true })
    allowGroupPurchase: boolean;

    @ApiProperty({
        description: 'Minimum group order quantity',
        nullable: true,
        example: 5,
    })
    minGroupOrderQuantity?: number;

    @ApiProperty({
        description: 'Group purchase price',
        nullable: true,
        example: 149.99,
    })
    groupPurchasePrice?: number;

    @ApiProperty({
        description: 'Group purchase duration (enum)',
        nullable: true,
        example: 'FIVE_DAYS',
        enum: GroupPurchaseDeadline,
    })
    groupPurchaseDuration?: GroupPurchaseDeadline;

    @ApiProperty({ description: 'Publish status', example: true })
    isPublished: boolean;

    @ApiProperty({
        description: 'Stock level of the product',
        enum: ['VERY LOW', 'LOW', 'AVERAGE', 'GOOD'],
        example: 'LOW',
    })
    stockStatus: 'VERY LOW' | 'LOW' | 'AVERAGE' | 'GOOD';

    @ApiProperty({
        description: 'Wishlist count (only shown if supplier has PREMIUM plan)',
        example: 10,
        required: false,
    })
    wishlistCount?: number;

    @ApiProperty({ description: 'Average rating', example: 4.5 })
    avgRating: number;

    @ApiProperty({ description: 'Ratings count', example: 12 })
    ratingsCount: number;

    @ApiProperty({ description: 'Creation timestamp' })
    createdAt: Date;

    @ApiProperty({ description: 'Last update timestamp' })
    updatedAt: Date;

    @ApiProperty({
        description: 'Indicates if the product is soft-deleted',
        example: false,
    })
    isDeleted: boolean;

    @ApiProperty({
        description:
            'Timestamp when the product was soft-deleted (null if not deleted)',
        nullable: true,
    })
    deletedAt?: Date | null;
}
