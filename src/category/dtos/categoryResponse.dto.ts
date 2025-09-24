import { ItemType } from '@prisma/client';
import { ApiProperty } from '@nestjs/swagger';

export class CategoryResponseDto {
    @ApiProperty({
        description: 'Unique identifier of the category',
        example: 1,
    })
    id: number;

    @ApiProperty({
        description: 'Name of the category',
        example: 'Agricultural & Pet Supplies',
    })
    name: string;

    @ApiProperty({
        description:
            'Specifies whether this category is for products or services',
        enum: ItemType,
        example: ItemType.PRODUCT,
    })
    usedFor: ItemType;

    @ApiProperty({
        description: 'Parent category, if this category is a subcategory',
        type: () => Object,
        example: { id: 1, name: 'Agricultural & Pet Supplies' },
        required: false,
    })
    parentCategory?: { id: number; name: string };

    @ApiProperty({
        description: 'Subcategories of this category, recursively nested',
        type: () => [CategoryResponseDto],
        example: [
            {
                id: 2,
                name: 'Pet Food & Treats',
                usedFor: ItemType.PRODUCT,
                parentCategory: { id: 1, name: 'Agricultural & Pet Supplies' },
                subcategories: [],
            },
            {
                id: 3,
                name: 'Pet Accessories & Toys',
                usedFor: ItemType.PRODUCT,
                parentCategory: { id: 1, name: 'Agricultural & Pet Supplies' },
                subcategories: [],
            },
        ],
        required: false,
    })
    subcategories?: CategoryResponseDto[];
}
