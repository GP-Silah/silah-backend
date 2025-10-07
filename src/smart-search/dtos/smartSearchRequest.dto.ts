import { IsOptional, IsString, ValidateIf } from 'class-validator';
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
    text?: string;
}
