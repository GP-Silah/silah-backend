import { ApiProperty } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import { UserResponseDTO } from 'src/user/dtos/userResponse.dto';

export class BuyerResponseDto {
    @ApiProperty({ type: () => UserResponseDTO })
    @Type(() => UserResponseDTO)
    user: UserResponseDTO;

    @ApiProperty({ type: String, required: false, example: 'tok_123456abcdef' })
    cardToken?: string;
}
