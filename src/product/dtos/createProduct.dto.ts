import {
    IsString,
    IsNotEmpty,
    IsOptional,
    IsNumber,
    IsPositive,
    IsInt,
    Min,
    Max,
    IsBoolean,
    IsArray,
    ArrayMinSize,
    ArrayMaxSize,
    ValidateIf,
    MaxLength,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { GroupPurchaseDeadline } from '@prisma/client';

export class CreateProductDto {
    @ApiPropertyOptional({
        description: 'Supplier ID',
    })
    @IsString()
    supplierId: string;

    @ApiProperty({
        description: 'Product name',
        example: 'Wireless Headphones',
        maxLength: 60,
    })
    @IsString()
    @IsNotEmpty()
    @MaxLength(60)
    name: string;

    @ApiProperty({
        description: 'Product description',
        example: 'Noise cancelling over-ear headphones',
        maxLength: 1000,
    })
    @IsString()
    @IsNotEmpty()
    @MaxLength(1000)
    description: string;

    @ApiProperty({ description: 'Product price', example: 199.99 })
    @IsNumber()
    @IsPositive()
    price: number;

    @ApiPropertyOptional({
        description: 'Available stock (default = 0)',
        example: 100,
    })
    @IsOptional()
    @IsInt()
    @Min(0)
    stock?: number;

    @ApiProperty({ description: 'Category ID', example: 1 })
    @IsInt()
    categoryId: number;

    @ApiProperty({
        description: 'Array of product image filenames',
        type: [String],
        example: ['img1.jpg', 'img2.jpg'],
    })
    @IsArray()
    @IsOptional()
    @ArrayMinSize(1)
    @ArrayMaxSize(3)
    @IsString({ each: true })
    imagesFilesNames: string[];

    @ApiPropertyOptional({
        description: 'Case quantity (default = 1)',
        example: 4,
    })
    @IsOptional()
    @IsInt()
    @Min(1)
    caseQuantity?: number;

    @ApiPropertyOptional({
        description: 'Minimum order quantity (default = 1)',
        example: 5,
    })
    @IsOptional()
    @IsInt()
    @Min(1)
    minOrderQuantity?: number;

    @ApiPropertyOptional({
        description: 'Maximum order quantity (null = unlimited)',
        example: 50,
    })
    @IsOptional()
    @IsInt()
    @Min(1)
    maxOrderQuantity?: number | null;

    @ApiPropertyOptional({
        description: 'Enable group purchase (default = false)',
    })
    @IsOptional()
    @IsBoolean()
    allowGroupPurchase?: boolean;

    @ApiPropertyOptional({
        description:
            'Minimum group order quantity (required if group purchase is enabled)',
        example: 10,
    })
    @ValidateIf((o) => o.allowGroupPurchase === true)
    @IsInt()
    @Min(1)
    minGroupOrderQuantity?: number;

    @ApiPropertyOptional({
        description:
            'Group purchase price (required if group purchase is enabled)',
        example: 149.99,
    })
    @ValidateIf((o) => o.allowGroupPurchase === true)
    @IsNumber()
    @IsPositive()
    groupPurchasePrice?: number;

    @ApiPropertyOptional({
        enum: GroupPurchaseDeadline,
        description: 'Group purchase duration (enum value)',
        example: 'SEVEN_DAYS',
    })
    @ValidateIf((o) => o.allowGroupPurchase === true)
    @IsString()
    groupPurchaseDuration?: GroupPurchaseDeadline;

    @ApiPropertyOptional({ description: 'Publish status (default = false)' })
    @IsOptional()
    @IsBoolean()
    isPublished?: boolean;
}
