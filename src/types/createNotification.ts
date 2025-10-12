import { NotificationEntityType, NotificationType } from '@prisma/client';

export interface CreateNotification {
    senderUserId: string;
    receiverUserId: string;
    type: NotificationType;
    title: string;
    content: string;
    entityId: string;
    entityType: NotificationEntityType;
}
