import { ApiProperty } from '@nestjs/swagger';

export class CardDetailsDto {
    @ApiProperty({
        description: 'Internal database ID of the card',
        example: 'f1a2b3c4-d5e6-7890-ab12-34567890cdef',
    })
    id: string;

    @ApiProperty({
        description: 'Tap payment gateway card ID',
        example: 'card_abc123xyz',
    })
    tapCardId: string;

    @ApiProperty({
        description: 'Name of the card holder',
        example: 'Norah Alqahtani',
    })
    cardHolderName: string;

    @ApiProperty({
        description: 'Last 4 digits of the card',
        example: '4242',
    })
    last4: string;

    @ApiProperty({
        description: 'Brand of the card (e.g., Visa, Mastercard)',
        example: 'Visa',
    })
    brand: string;

    @ApiProperty({
        description: 'Expiration month of the card (1-12)',
        example: 12,
    })
    expMonth: string;

    @ApiProperty({
        description: 'Expiration year of the card',
        example: 31,
    })
    expYear: string;
}
