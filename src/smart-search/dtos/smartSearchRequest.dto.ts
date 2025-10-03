import { ItemType } from '@prisma/client';
import { IsOptional, IsString, IsEnum, ValidateIf } from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class SmartSearchRequestDto {
    @ApiPropertyOptional({
        description:
            'ID of an existing item (product or service) to find similar alternatives',
        example: 'ferew32-gr45-dfg5-34g5-34g53',
    })
    @IsOptional()
    @IsString()
    itemId?: string;

    @ApiPropertyOptional({
        description:
            'Name of the item to search by (required if no itemId is provided)',
        example: 'Wooden Brush',
    })
    @ValidateIf((o) => !o.itemId)
    @IsString()
    itemName?: string;

    @ApiPropertyOptional({
        description:
            'Optional description of the item to improve similarity matching',
        example: 'A brown wooden brush for cleaning shoes',
    })
    @IsOptional()
    @IsString()
    itemDescription?: string;

    @ApiPropertyOptional({
        description: 'Type of item being searched',
        enum: ItemType,
        example: ItemType.PRODUCT,
    })
    @IsOptional()
    @IsEnum(ItemType)
    itemType?: ItemType;

    @ApiPropertyOptional({
        description: 'Optional category ID to limit search within a category',
        example: 12,
    })
    @IsOptional()
    categoryId?: number;
}
