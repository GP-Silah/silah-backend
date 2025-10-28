import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString } from 'class-validator';

export class PayInvoiceDto {
    @ApiPropertyOptional({
        description:
            'Existing chargeId to confirm payment instead of creating a new one (Step 2)',
        example: 'chg_TS00022120250302grEG302115114',
    })
    @IsOptional()
    @IsString()
    chargeId?: string;

    @ApiPropertyOptional({
        description:
            'Frontend redirect URL where the user will be sent after completing the OTP/3DS flow (Step 1)',
        example:
            'https://yourapp.com/buyer/payment/callback or http://localhost:5137/buyer/payment/callback in testing environment',
    })
    @IsOptional()
    @IsString()
    redirectUrl?: string;
}
