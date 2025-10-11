import { IsArray, IsUUID } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class MarkAsReadDto {
    @ApiProperty({
        description: 'Array of notification IDs to mark as read',
        type: [String],
        example: ['uuid-1', 'uuid-2', 'uuid-3'],
    })
    @IsArray()
    @IsUUID('4', { each: true })
    notificationIds: string[];
}
