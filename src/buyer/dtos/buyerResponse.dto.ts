import { ApiProperty } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import { UserResponseDTO } from 'src/user/dtos/userResponse.dto';
import { CardDetailsDto } from './cardDetails.dto';

export class BuyerResponseDto {
    @ApiProperty({ type: () => UserResponseDTO })
    @Type(() => UserResponseDTO)
    user: UserResponseDTO;

    @ApiProperty({ type: () => CardDetailsDto, nullable: true })
    @Type(() => CardDetailsDto)
    card: CardDetailsDto;
}
