import { UserService } from 'src/user/user.service';
import {
    BadRequestException,
    ForbiddenException,
    Injectable,
    NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { UpdateNotificationPreferencesDto } from './dtos/updateNotificationPreference.dto';
import { NotificationType, UserRole } from '@prisma/client';
import { NotificationResponseDto } from './dtos/notificationResponse.dto';
import { MarkAsReadDto } from './dtos/markReadBulk.dto';
import { startOfDay, startOfWeek, startOfMonth } from 'date-fns';
import { Subject } from 'rxjs';
import { CreateNotification } from 'src/types/createNotification';

@Injectable()
export class NotificationService {
    private readonly notifications$ = new Subject<{
        receiverUserId: string;
        notification: NotificationResponseDto;
    }>();

    constructor(
        private readonly prisma: PrismaService,
        private readonly userService: UserService,
    ) {}

    async toNotificationResponseDto(
        notification: any,
    ): Promise<NotificationResponseDto> {
        return {
            notificationId: notification.id,
            sender: await this.userService.toUserResponseDTO(
                notification.sender,
            ),
            receiver: await this.userService.toUserResponseDTO(
                notification.receiver,
            ),
            notificationType: notification.notificationType,
            title: notification.title,
            content: notification.content,
            isRead: notification.isRead,
            readAt: notification.readAt,
            createdAt: notification.createdAt,
            relatedEntityId: notification.relatedEntityId ?? undefined,
            relatedEntityType: notification.relatedEntityType ?? undefined,
        };
    }

    async updateNotificationPreferences(
        userId: string,
        dto: UpdateNotificationPreferencesDto,
    ) {
        // Step 1: Get the user and their role
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
            select: { id: true, role: true },
        });

        if (!user) throw new NotFoundException('User not found');

        // Step 2: Get existing preferences or create default
        const existingPrefs =
            await this.prisma.notificationPreference.findUnique({
                where: { userId },
            });

        if (!existingPrefs) {
            await this.prisma.notificationPreference.create({
                data: { userId },
            });
        }

        // Step 3: Define allowed fields per role
        const baseFields = ['allowNotifications', 'newMessageNotify'];
        const supplierFields = [
            ...baseFields,
            'newOrderNotify',
            'newReviewNotify',
            'biddingStatusNotify',
            'invoiceStatusNotify',
        ];
        const buyerFields = [
            ...baseFields,
            'newInvoiceNotify',
            'newOfferNotify',
            'orderStatusNotify',
            'groupPurchaseStatusNotify',
        ];

        let allowedFields: string[];
        if (user.role === UserRole.SUPPLIER) allowedFields = supplierFields;
        else if (user.role === UserRole.BUYER) allowedFields = buyerFields;
        else {
            throw new ForbiddenException(
                'Unsupported user role for notifications',
            );
        }

        // Step 4: Filter out invalid keys (not allowed for this role)
        const filteredUpdate = Object.entries(dto).reduce(
            (acc, [key, value]) => {
                if (allowedFields.includes(key)) acc[key] = value;
                return acc;
            },
            {} as Record<string, boolean>,
        );

        if (Object.keys(filteredUpdate).length === 0) {
            throw new ForbiddenException(
                'No valid preferences to update for this role',
            );
        }

        // Step 5: Update preferences
        const updated = await this.prisma.notificationPreference.update({
            where: { userId },
            data: filteredUpdate,
        });

        return {
            message: 'Notification preferences updated successfully',
            newNotificationPreferences: updated,
        };
    }

    async getMyNotifications(
        userId: string,
        date: string = 'all',
        notificationType?: string,
    ): Promise<NotificationResponseDto[]> {
        // Step 1: Build dynamic Prisma filter
        const where: any = {
            receiverUserId: userId,
        };

        // --- Handle date filter ---
        const now = new Date();
        let startDate: Date | undefined;

        switch (date?.toLowerCase()) {
            case 'today':
                startDate = startOfDay(now);
                break;
            case 'this-week':
                startDate = startOfWeek(now, { weekStartsOn: 0 }); // week starts on Sunday
                break;
            case 'this-month':
                startDate = startOfMonth(now);
                break;
            case 'all':
            case undefined:
                break;
            default:
                throw new BadRequestException(
                    "Invalid 'date' filter. Use: all, today, this-week, this-month",
                );
        }

        if (startDate) {
            where.createdAt = { gte: startDate };
        }

        // --- Handle type filter ---
        if (notificationType) {
            const upper = notificationType.toUpperCase();

            if (!(upper in NotificationType)) {
                throw new BadRequestException(
                    `Invalid notification type: ${notificationType}`,
                );
            }

            where.notificationType = upper as NotificationType;
        }

        // Step 2: Query notifications
        const notifications = await this.prisma.notification.findMany({
            where,
            include: {
                sender: true,
                receiver: true,
            },
            orderBy: { createdAt: 'desc' },
        });

        if (!notifications.length) return [];

        // Step 3: Convert to DTOs
        return Promise.all(
            notifications.map((n) => this.toNotificationResponseDto(n)),
        );
    }

    async markNotificationAsRead(userId: string, notificationId: string) {
        // Step 1: Find the notification
        const notification = await this.prisma.notification.findUnique({
            where: { id: notificationId },
            include: { sender: true, receiver: true },
        });

        if (!notification) {
            throw new NotFoundException('Notification not found');
        }

        // Step 2: Verify ownership (receiver must be the logged-in user)
        if (notification.receiverUserId !== userId) {
            throw new ForbiddenException(
                'You are not authorized to modify this notification',
            );
        }

        // Step 3: Update only if it’s not already read
        if (!notification.isRead) {
            await this.prisma.notification.update({
                where: { id: notificationId },
                data: { isRead: true, readAt: new Date() },
            });
        }

        // Step 4: Return the updated DTO
        const updated = await this.prisma.notification.findUnique({
            where: { id: notificationId },
            include: { sender: true, receiver: true },
        });

        return this.toNotificationResponseDto(updated);
    }

    async markNotificationsAsReadInBulk(userId: string, dto: MarkAsReadDto) {
        const { notificationIds } = dto;

        if (!notificationIds || notificationIds.length === 0) {
            throw new ForbiddenException('No notification IDs provided');
        }

        // Step 1: Get notifications belonging to this user
        const userNotifications = await this.prisma.notification.findMany({
            where: {
                id: { in: notificationIds },
                receiverUserId: userId,
            },
        });

        if (userNotifications.length === 0) {
            throw new NotFoundException(
                'No valid notifications found for this user',
            );
        }

        // Step 2: Filter unread ones to avoid unnecessary updates
        const unreadIds = userNotifications
            .filter((n) => !n.isRead)
            .map((n) => n.id);

        if (unreadIds.length === 0) {
            return {
                message: 'All notifications are already marked as read',
                updatedCount: 0,
            };
        }

        // Step 3: Bulk update using updateMany
        const result = await this.prisma.notification.updateMany({
            where: {
                id: { in: unreadIds },
                receiverUserId: userId,
            },
            data: {
                isRead: true,
                readAt: new Date(),
            },
        });

        // Step 4: Return response summary
        return {
            message: `Successfully marked ${result.count} notification(s) as read`,
            updatedCount: result.count,
        };
    }

    getNotificationStream() {
        return this.notifications$.asObservable();
    }

    async createNotification(
        data: CreateNotification,
    ): Promise<NotificationResponseDto> {
        // Step 1: Create the notification in the database
        const notification = await this.prisma.notification.create({
            data: {
                senderUserId: data.senderUserId,
                receiverUserId: data.receiverUserId,
                type: data.type,
                title: data.title,
                content: data.content,
                entityId: data.entityId,
                entityType: data.entityType,
            },
            include: { sender: true, receiver: true },
        });

        // Step 2: Convert to DTO
        const dto = await this.toNotificationResponseDto(notification);

        // Step 3: Emit to stream subscribers
        this.notifications$.next({
            receiverUserId: data.receiverUserId,
            notification: dto,
        });

        return dto;
    }
}
