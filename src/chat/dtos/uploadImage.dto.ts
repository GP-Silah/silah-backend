import { ApiProperty } from '@nestjs/swagger';
import { IsUUID } from 'class-validator';

export class UploadImageDto {
    @ApiProperty({
        description: 'UUID of the user sending the image',
        example: 'a7f8b2c3-5d1e-4c29-91f7-2bcf6d8a91a2',
    })
    @IsUUID()
    senderId: string;

    @ApiProperty({
        description: 'UUID of the user receiving the image',
        example: 'b9e4dc08-0c63-4c2b-b7f5-41e7e49b6222',
    })
    @IsUUID()
    receiverId: string;
}
