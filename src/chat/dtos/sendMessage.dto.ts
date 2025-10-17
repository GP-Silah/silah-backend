import { IsOptional, IsString, IsUUID } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class SendMessageDto {
    @ApiPropertyOptional({
        description: 'The chat ID. Optional because a chat may not exist yet.',
        type: String,
        format: 'uuid',
        example: 'dgserhbrt-324okpo-43v5rgb',
    })
    @IsOptional()
    @IsUUID()
    chatId?: string;

    @ApiProperty({
        description: 'The UUID of the receiver',
        type: String,
        format: 'uuid',
        example: '24ter-4t54ty45w-fadge4r',
    })
    @IsUUID()
    receiverId: string;

    @ApiProperty({
        description: 'The message text to send. Cannot be empty.',
        type: String,
        example: 'Hello!',
    })
    @IsString()
    text: string;
}
