import {
    IsOptional,
    IsString,
    MaxLength,
    IsNumber,
    IsPositive,
    IsInt,
    Min,
    IsBoolean,
    IsArray,
    ArrayMinSize,
    ArrayMaxSize,
    ValidateIf,
} from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';
import { GroupPurchaseDeadline } from '@prisma/client';
import { IsMultipleOfCaseQuantity } from './is-multiple-of-case-quantity.validator';

export class UpdateProductDto {
    @ApiPropertyOptional({ description: 'Product name', maxLength: 60 })
    @IsOptional()
    @IsString()
    @MaxLength(60)
    name?: string;

    @ApiPropertyOptional({
        description: 'Product description',
        maxLength: 1000,
    })
    @IsOptional()
    @IsString()
    @MaxLength(1000)
    description?: string;

    @ApiPropertyOptional({ description: 'Product price', example: 199.99 })
    @IsOptional()
    @IsNumber()
    @IsPositive()
    price?: number;

    @ApiPropertyOptional({ description: 'Available stock', example: 100 })
    @IsOptional()
    @IsInt()
    @Min(0)
    stock?: number;

    @ApiPropertyOptional({ description: 'Category ID', example: 1 })
    @IsOptional()
    @IsInt()
    categoryId?: number;

    @ApiPropertyOptional({ description: 'Case quantity', example: 1 })
    @IsOptional()
    @IsInt()
    @Min(1)
    caseQuantity?: number;

    @ApiPropertyOptional({ description: 'Minimum order quantity', example: 1 })
    @IsOptional()
    @IsInt()
    @Min(1)
    @IsMultipleOfCaseQuantity({
        message: 'minOrderQuantity must be a multiple of caseQuantity',
    })
    minOrderQuantity?: number;

    @ApiPropertyOptional({
        description: 'Maximum order quantity (null = unlimited)',
        example: 50,
    })
    @IsOptional()
    @IsInt()
    @Min(1)
    @IsMultipleOfCaseQuantity({
        message: 'maxOrderQuantity must be a multiple of caseQuantity',
    })
    maxOrderQuantity?: number | null;

    @ApiPropertyOptional({
        description: 'Enable group purchase',
        example: false,
    })
    @IsOptional()
    @IsBoolean()
    allowGroupPurchase?: boolean;

    @ApiPropertyOptional({
        description: 'Minimum group order quantity',
        example: 5,
    })
    @ValidateIf((o) => o.allowGroupPurchase === true)
    @IsOptional()
    @IsInt()
    @Min(1)
    minGroupOrderQuantity?: number;

    @ApiPropertyOptional({
        description: 'Group purchase price',
        example: 149.99,
    })
    @ValidateIf((o) => o.allowGroupPurchase === true)
    @IsOptional()
    @IsNumber()
    @IsPositive()
    groupPurchasePrice?: number;

    @ApiPropertyOptional({
        description: 'Group purchase duration (enum)',
        example: 'ONE_WEEK',
        enum: GroupPurchaseDeadline,
    })
    @ValidateIf((o) => o.allowGroupPurchase === true)
    @IsOptional()
    @IsString()
    groupPurchaseDuration?: GroupPurchaseDeadline;

    @ApiPropertyOptional({ description: 'Publish status', example: false })
    @IsOptional()
    @IsBoolean()
    isPublished?: boolean;
}
