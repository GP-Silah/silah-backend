import { ApiProperty, getSchemaPath } from '@nestjs/swagger';
import { ProductResponseDto } from 'src/product/dtos/productResponse.dto';
import { ServiceResponseDto } from 'src/service/dtos/serviceResponse.dto';

export class SmartSearchResponseDto {
    @ApiProperty({
        description: 'The text used by the backend for this smart search',
        example: 'Organic Honey 500g',
    })
    text: string;

    @ApiProperty({
        description: 'The matched item (product or service)',
        oneOf: [
            { $ref: getSchemaPath(ProductResponseDto) },
            { $ref: getSchemaPath(ServiceResponseDto) },
        ],
    })
    item: ProductResponseDto | ServiceResponseDto;

    @ApiProperty({
        description:
            'Ranking position among the top results (1 = most similar)',
        example: 1,
    })
    rank: number;
}
