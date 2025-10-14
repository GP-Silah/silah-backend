import { ApiProperty } from '@nestjs/swagger';
import { IsArray, IsUUID } from 'class-validator';

export class MarkMessageAsReadDto {
    @ApiProperty({
        description:
            'Array of message UUIDs to mark as read. Each must be a valid UUID v4.',
        example: [
            'd7a1b5d2-83c2-4a91-a1a0-8d5f3e2e9f11',
            '8a2b7d91-13f1-42ac-8c2f-9b4b0f5d8c22',
        ],
    })
    @IsArray()
    @IsUUID('4', { each: true })
    messageIds: string[];
}
