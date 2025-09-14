import { IsNotEmpty, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateCardDto {
    @ApiProperty({
        description:
            "Tap token received from the frontend after card tokenization process (using Tap's Card SDK)",
        example: 'tok_TS57A39251831Q2B15Ro8l180',
    })
    @IsNotEmpty()
    @IsString()
    token: string;
}
