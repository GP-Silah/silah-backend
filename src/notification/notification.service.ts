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
import { MarkNotificationsAsReadDto } from './dtos/markNotificationsReadBulk.dto';
import { startOfDay, startOfWeek, startOfMonth } from 'date-fns';
import { Subject } from 'rxjs';
import { CreateNotification } from 'src/types/createNotification';
import { TranslationService } from 'src/translation/translation.service';

@Injectable()
export class NotificationService {
    private readonly notifications$ = new Subject<{
        receiverUserId: string;
        notification: NotificationResponseDto;
    }>();

    constructor(
        private readonly prisma: PrismaService,
        private readonly userService: UserService,
        private readonly translationService: TranslationService,
    ) {}

    /** Helper: get user preferred language */
    async getUserLanguage(userId: string): Promise<'ar' | 'en' | null> {
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
            select: { preferredLanguage: true },
        });
        const lang = user?.preferredLanguage?.toLowerCase();
        return lang === 'ar' || lang === 'en' ? lang : null;
    }

    /** Helper: translate notification title/content */
    async translateNotification(
        notification: NotificationResponseDto,
        targetLang: 'ar' | 'en',
    ): Promise<NotificationResponseDto> {
        if (!notification || targetLang === 'en') return notification;

        const [translatedTitle, translatedContent] = await Promise.all([
            this.translationService.translateText(
                notification.title,
                targetLang,
            ),
            this.translationService.translateText(
                notification.content,
                targetLang,
            ),
        ]);

        return {
            ...notification,
            title: translatedTitle,
            content: translatedContent,
        };
    }

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
            relatedEntityId: notification.entityId,
            relatedEntityType: notification.entityType,
        };
    }

    async getNotificationPreferences(userId: string) {
        // Step 1: Get the user and their role
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
            select: { id: true, role: true },
        });

        if (!user) throw new NotFoundException('User not found');

        // Step 2: Get existing preferences or create default
        let prefs = await this.prisma.notificationPreference.findUnique({
            where: { userId },
        });

        if (!prefs) {
            prefs = await this.prisma.notificationPreference.create({
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

        // Step 4: Pick only allowed fields
        const filteredPrefs: Record<string, boolean> = {};
        for (const key of allowedFields) {
            filteredPrefs[key] = prefs[key];
        }

        return {
            message: 'Notification preferences retrieved successfully',
            notificationPreferences: filteredPrefs,
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
            throw new BadRequestException(
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
        targetLang?: 'ar' | 'en',
    ): Promise<NotificationResponseDto[]> {
        // --- Step 0: Get user role (we use it to decide which notification types are relevant) ---
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
            select: { role: true },
        });

        if (!user) {
            throw new NotFoundException('User not found');
        }

        // Define allowed notification types per role
        const SUPPLIER_NOTIFICATION_TYPES: NotificationType[] = [
            'NEW_MESSAGE',
            'NEW_ORDER',
            'NEW_REVIEW',
            'BID_STATUS_CHANGED',
            'INVOICE_STATUS_CHANGED',
        ];

        const BUYER_NOTIFICATION_TYPES: NotificationType[] = [
            'NEW_MESSAGE',
            'NEW_INVOICE',
            'NEW_OFFER',
            'ORDER_STATUS_CHANGED',
            'GROUP_PURCHASE_STATUS_CHANGED',
        ];

        const allowedTypes =
            user.role === UserRole.SUPPLIER
                ? SUPPLIER_NOTIFICATION_TYPES
                : user.role === UserRole.BUYER
                  ? BUYER_NOTIFICATION_TYPES
                  : [];

        if (allowedTypes.length === 0) {
            // If there is an unsupported role, fail fast
            throw new ForbiddenException(
                'Unsupported user role for notifications',
            );
        }

        // --- Step 1: Build dynamic Prisma filter ---
        const where: any = {
            receiverUserId: userId,
            // Only notifications relevant to this role
            type: { in: allowedTypes },
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

        // --- Handle type filter (user asked for a specific type) ---
        if (notificationType) {
            const upper = notificationType.toUpperCase();

            // Validate requested type is a valid NotificationType
            const validNotificationTypes = Object.values(NotificationType);
            if (!validNotificationTypes.includes(upper as NotificationType)) {
                throw new BadRequestException(
                    `Invalid notification type: ${notificationType}`,
                );
            }

            // If requested type is valid but not allowed for this role -> forbidden
            if (!allowedTypes.includes(upper as NotificationType)) {
                throw new ForbiddenException(
                    `Notification type '${upper}' is not available for the current user role`,
                );
            }

            // Narrow the query by the specific requested type
            where.type = upper;
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

        // Step 3: Convert to DTO
        const dtos = await Promise.all(
            notifications.map((n) => this.toNotificationResponseDto(n)),
        );

        // Step 4: Translate title/content of the notification
        if (targetLang && targetLang !== 'en') {
            return Promise.all(
                dtos.map((dto) => this.translateNotification(dto, targetLang)),
            );
        }

        return dtos;
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

    async markNotificationsAsReadInBulk(
        userId: string,
        dto: MarkNotificationsAsReadDto,
    ) {
        const { notificationIds } = dto;

        if (!notificationIds || notificationIds.length === 0) {
            throw new BadRequestException('No notification IDs provided');
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

        // Step 2.5: Load notification preferences
        const preference = await this.prisma.notificationPreference.findUnique({
            where: { userId: data.receiverUserId },
        });

        const userLang = await this.getUserLanguage(data.receiverUserId);

        // Translate before emitting
        const translatedDto =
            userLang && userLang !== 'en'
                ? await this.translateNotification(dto, userLang)
                : dto;

        // Step 3: Emit based on preference
        if (preference?.allowNotifications) {
            let shouldSend = false;

            switch (data.type) {
                case 'NEW_MESSAGE':
                    shouldSend = preference.newMessageNotify;
                    break;
                case 'NEW_ORDER':
                    shouldSend = preference.newOrderNotify;
                    break;
                case 'NEW_REVIEW':
                    shouldSend = preference.newReviewNotify;
                    break;
                case 'NEW_INVOICE':
                    shouldSend = preference.newInvoiceNotify;
                    break;
                case 'NEW_OFFER':
                    shouldSend = preference.newOfferNotify;
                    break;
                case 'BID_STATUS_CHANGED':
                    shouldSend = preference.biddingStatusNotify;
                    break;
                case 'INVOICE_STATUS_CHANGED':
                    shouldSend = preference.invoiceStatusNotify;
                    break;
                case 'ORDER_STATUS_CHANGED':
                    shouldSend = preference.orderStatusNotify;
                    break;
                case 'GROUP_PURCHASE_STATUS_CHANGED':
                    shouldSend = preference.groupPurchaseStatusNotify;
                    break;
                default:
                    shouldSend = false;
            }

            if (shouldSend) {
                this.notifications$.next({
                    receiverUserId: data.receiverUserId,
                    notification: translatedDto,
                });
            }
        }

        return translatedDto;
    }
}
