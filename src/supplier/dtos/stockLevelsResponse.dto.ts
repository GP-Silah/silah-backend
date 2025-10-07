import { ApiProperty } from '@nestjs/swagger';

export class StockProductDto {
    @ApiProperty({ example: 'uuid-prod-1', description: 'Product ID' })
    productId: string;

    @ApiProperty({
        example: 'Classic Wooden Hair Brush',
        description: 'Product name',
    })
    name: string;

    @ApiProperty({ example: 3, description: 'Current stock of the product' })
    stock: number;
}

export class StockGroupDto {
    @ApiProperty({
        example: 2,
        description: 'Number of products in this stock group',
    })
    count: number;

    @ApiProperty({
        type: [StockProductDto],
        description: 'List of products in this stock group',
    })
    products: StockProductDto[];
}

export class StockLevelsResponseDto {
    @ApiProperty({
        example: 'uuid-supplier-id',
        description: 'ID of the supplier',
    })
    supplierId: string;

    @ApiProperty({
        description: 'Overview of all products grouped by stock level',
        type: () => ({
            VERY_LOW: StockGroupDto,
            LOW: StockGroupDto,
            AVERAGE: StockGroupDto,
            GOOD: StockGroupDto,
        }),
    })
    overview: {
        VERY_LOW: StockGroupDto;
        LOW: StockGroupDto;
        AVERAGE: StockGroupDto;
        GOOD: StockGroupDto;
    };
}
