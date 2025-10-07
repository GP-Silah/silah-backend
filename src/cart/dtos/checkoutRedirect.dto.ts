// dtos/checkoutRedirect.dto.ts
import { ApiProperty } from '@nestjs/swagger';

export class CheckoutRedirectDto {
    @ApiProperty({
        description: 'Message indicating 3DS authentication is required',
        example: 'Redirect for authentication',
    })
    message: string;

    @ApiProperty({
        description:
            'URL where the buyer should be redirected for 3DS authentication',
        example: 'https://tap.company/3ds/redirect',
    })
    redirectUrl: string;

    @ApiProperty({
        description: 'Tap charge ID for this transaction',
        example: 'chg_TK12GF345W843R',
    })
    chargeId: string;
}
