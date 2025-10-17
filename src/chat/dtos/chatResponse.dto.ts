import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { UserResponseDTO } from 'src/user/dtos/userResponse.dto';

export class ChatResponseDto {
    @ApiProperty({
        description: 'Unique identifier of the chat',
        example: 'a3f8b2d6-1b2c-4f59-81b3-2cf8d6a9d3b5',
    })
    chatId: string;

    @ApiProperty({
        description:
            'The other participant in this chat (not the logged-in user)',
        type: () => UserResponseDTO,
    })
    otherUser: UserResponseDTO;

    @ApiPropertyOptional({
        description: 'Text of the latest message in the chat, if any',
        example: "Are you available for tomorrow's delivery?",
    })
    lastMessageText?: string;

    @ApiPropertyOptional({
        description:
            'Indicates whether the latest message in the chat is an image. ' +
            'If true, the frontend can display a label like "Image" instead of showing message text. ' +
            "Note: this field does not contain the image URL; it's a simple boolean flag.",
        example: true,
    })
    lastMessageIsImage: boolean;

    @ApiProperty({
        description: 'Timestamp of when the latest message was sent',
        example: '2025-10-13T18:45:00.000Z',
    })
    lastMessageAt: Date;

    @ApiProperty({
        description:
            'Number of unread messages for the logged-in user in this chat',
        example: 2,
    })
    unreadCount: number;
}
