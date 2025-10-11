import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { NotificationEntityType, NotificationType } from '@prisma/client';
import { UserResponseDTO } from 'src/user/dtos/userResponse.dto';

export class NotificationResponseDto {
    @ApiProperty({ description: 'Unique identifier of the notification' })
    notificationId: string;

    @ApiProperty({
        type: () => UserResponseDTO,
        description: 'User who sent the notification',
    })
    sender: UserResponseDTO;

    @ApiProperty({
        type: () => UserResponseDTO,
        description: 'User who receives the notification',
    })
    receiver: UserResponseDTO;

    @ApiProperty({
        enum: NotificationType,
        description: 'Type of the notification',
    })
    notificationType: NotificationType;

    @ApiProperty({ description: 'Title of the notification' })
    title: string;

    @ApiProperty({ description: 'Content/body of the notification' })
    content: string;

    @ApiProperty({ description: 'Indicates if the notification has been read' })
    isRead: boolean;

    @ApiPropertyOptional({
        description: 'Timestamp when the notification was read, if applicable',
    })
    readAt?: Date;

    @ApiProperty({ description: 'Timestamp when the notification was created' })
    createdAt: Date;

    @ApiPropertyOptional({
        description: 'ID of the related entity (e.g., order, chat message)',
    })
    relatedEntityId?: string;

    @ApiPropertyOptional({
        enum: NotificationEntityType,
        description: 'Type of the related entity',
    })
    relatedEntityType?: NotificationEntityType;
}
