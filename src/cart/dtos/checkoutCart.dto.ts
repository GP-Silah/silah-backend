import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString } from 'class-validator';

export class CheckoutCartDto {
    @ApiPropertyOptional({
        description:
            'Existing chargeId to confirm payment instead of creating a new one',
        example: 'chg_TS00022120250302grEG302115114',
    })
    @IsOptional()
    @IsString()
    chargeId?: string;
}
