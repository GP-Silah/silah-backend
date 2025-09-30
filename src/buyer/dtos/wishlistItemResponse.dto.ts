import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { ItemType } from '@prisma/client';
import { ProductResponseDto } from 'src/product/dtos/productResponse.dto';
import { ServiceResponseDto } from 'src/service/dtos/serviceResponse.dto';

export class WishlistItemResponseDto {
    @ApiProperty({
        description:
            'The ID of the wishlist item (which is the id of the product or service)',
        example: 'd4f2a1b0-1234-5678-9abc-1234567890ab',
    })
    itemId: string;

    @ApiProperty({
        description: 'The type of the item in the wishlist',
        enum: ItemType,
        example: ItemType.PRODUCT,
    })
    itemType: ItemType;

    @ApiPropertyOptional({
        description: 'The product details, present only if itemType is PRODUCT',
        type: () => ProductResponseDto,
    })
    product?: ProductResponseDto;

    @ApiPropertyOptional({
        description: 'The service details, present only if itemType is SERVICE',
        type: () => ServiceResponseDto,
    })
    service?: ServiceResponseDto;
}
