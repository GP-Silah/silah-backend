import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { UserResponseDTO } from 'src/user/dtos/userResponse.dto';

export class MessageResponseDto {
    @ApiProperty({
        description: 'Unique identifier of the message',
        example: 'a9e4dc08-0c63-4c2b-b7f5-41e7e49b6222',
    })
    messageId: string;

    @ApiProperty({
        description: 'ID of the chat this message belongs to',
        example: '3c2f90b7-6b0e-42d4-a5d3-c7f21c8b1f77',
    })
    chatId: string;

    @ApiProperty({
        description: 'User who sent the message',
        type: () => UserResponseDTO,
    })
    sender: UserResponseDTO;

    @ApiProperty({
        description: 'User who received the message',
        type: () => UserResponseDTO,
    })
    receiver: UserResponseDTO;

    @ApiPropertyOptional({
        description:
            'Text content of the message (if it is not an image-only message)',
        example: 'Hello! How are you?',
    })
    text?: string;

    @ApiPropertyOptional({
        description:
            'Signed URL from R2 of the image attached to this message (if any). Signed URLs expire 1 hour after creation.',
        example:
            'https://gp-silah.d025be9440ae5eb8295c69a36497276a.r2.cloudflarestorage.com/gp-silah/moon.jpeg-30510246-41f7-4cff-a052-78bcc30f7301.jpeg?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=...&X-Amz-Date=20250816T131236Z&X-Amz-Expires=3600&X-Amz-Signature=...',
        format: 'uri',
    })
    imageUrl?: string;

    @ApiProperty({
        description: 'Whether the receiver has read the message',
        example: false,
    })
    isRead: boolean;

    @ApiPropertyOptional({
        description: 'Timestamp when the message was read (if applicable)',
        example: '2025-10-13T18:45:00.000Z',
    })
    readAt?: Date;

    @ApiProperty({
        description: 'Timestamp when the message was created/sent',
        example: '2025-10-13T18:40:00.000Z',
    })
    createdAt: Date;
}
