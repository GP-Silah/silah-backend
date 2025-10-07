// DTOs
import { IsNotEmpty, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateCardStep1Dto {
    @ApiProperty({
        description:
            "Tap token id received from the frontend after card tokenization process (using Tap's Card SDK)",
        example: 'tok_TS57A39251831Q2B15Ro8l180',
    })
    @IsNotEmpty()
    @IsString()
    tokenId: string;

    @ApiProperty({
        description:
            'Frontend redirect URL where the user will be sent after completing the OTP/3DS flow',
        example:
            'https://yourapp.com/payment/callback or http://localhost:5137/payment/callback in testing environment',
    })
    @IsNotEmpty()
    @IsString()
    redirectUrl: string;
}

export class CreateCardStep2Dto {
    @ApiProperty({
        description:
            'Charge id returned in Step 1 (to validate status before saving card)',
        example: 'chg_TS50A42252049msSJ23MV8k170',
    })
    @IsNotEmpty()
    @IsString()
    chargeId: string;
}
