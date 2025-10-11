import { ApiProperty } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import { UserResponseDTO } from 'src/user/dtos/userResponse.dto';
import { CardDetailsDto } from './cardDetails.dto';

export class BuyerResponseDto {
    @ApiProperty({
        description: 'The buyer ID.',
        example: '2343dsfawaf-sarfe3-dg45-bfc',
    })
    buyerId: string;

    @ApiProperty({ type: () => UserResponseDTO })
    @Type(() => UserResponseDTO)
    user: UserResponseDTO;

    @ApiProperty({ type: () => CardDetailsDto, nullable: true })
    @Type(() => CardDetailsDto)
    card: CardDetailsDto | null;
}
