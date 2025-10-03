import { ApiProperty, getSchemaPath } from '@nestjs/swagger';
import { ProductResponseDto } from 'src/product/dtos/productResponse.dto';
import { ServiceResponseDto } from 'src/service/dtos/serviceResponse.dto';

export class SmartSearchResponseDto {
    @ApiProperty({
        description: 'The matched item (product or service)',
        oneOf: [
            { $ref: getSchemaPath(ProductResponseDto) },
            { $ref: getSchemaPath(ServiceResponseDto) },
        ],
    })
    item: ProductResponseDto | ServiceResponseDto;

    @ApiProperty({
        description: 'Cosine similarity score between 0 and 1',
        example: 0.87,
    })
    similarityScore: number;
}
