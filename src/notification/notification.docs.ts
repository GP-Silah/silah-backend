import { applyDecorators } from '@nestjs/common';
import {
    ApiOperation,
    ApiResponse,
    ApiBearerAuth,
    ApiBadRequestResponse,
    ApiNotFoundResponse,
    ApiBody,
    ApiQuery,
} from '@nestjs/swagger';
import { NotificationResponseDto } from './dtos/notificationResponse.dto';
import { UpdateNotificationPreferencesDto } from './dtos/updateNotificationPreference.dto';
import { MarkAsReadDto } from './dtos/markReadBulk.dto';
import { NotificationType } from '@prisma/client';

export function ApiDocsUpdateNotificationPreferences() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Update my notification preferences',
            description: `Allows the authenticated user to update their notification preferences.
                <ul>
                    <li>Suppliers can modify: new orders, new reviews, bidding status, invoice status.</li>
                    <li>Buyers can modify: new invoices, new offers, order status, group purchase status.</li>
                    <li>All users can toggle all notifications or new message notifications.</li>
                </ul>`,
        }),
        ApiBody({ type: UpdateNotificationPreferencesDto }),
        ApiResponse({
            status: 200,
            description: 'Notification preferences updated successfully',
            schema: {
                example: {
                    message: 'Notification preferences updated successfully',
                    newNotificationPreferences: {
                        userId: 'user-uuid',
                        allowNotifications: true,
                        newMessageNotify: true,
                        newOrderNotify: true,
                        newReviewNotify: true,
                        biddingStatusNotify: true,
                        invoiceStatusNotify: true,
                        newInvoiceNotify: true,
                        newOfferNotify: true,
                        orderStatusNotify: true,
                        groupPurchaseStatusNotify: true,
                        createdAt: '2025-01-01T00:00:00.000Z',
                        updatedAt: '2025-01-01T00:00:00.000Z',
                    },
                },
            },
        }),
        ApiBadRequestResponse({
            description:
                'Invalid request body or unsupported fields for this role',
            schema: {
                example: {
                    statusCode: 400,
                    message: 'No valid preferences to update for this role',
                    error: 'Bad Request',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'User not found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'User not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsGetMyNotifications() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Get my notifications',
            description: `Fetch notifications for the authenticated user.
                <ul>
                    <li>You can filter by date using query: <code>today</code>, <code>this-week</code>, <code>this-month</code>, <code>all</code> (default: all)</li>
                    <li>You can filter by notification type using the <code>type</code> query parameter.</li>
                </ul>`,
        }),
        ApiQuery({
            name: 'date',
            required: false,
            description: 'Filter notifications by date',
            example: 'today',
        }),
        ApiQuery({
            name: 'type',
            required: false,
            description: 'Filter notifications by type',
            enum: NotificationType,
            example: 'NEW_MESSAGE',
        }),
        ApiResponse({
            status: 200,
            description: 'List of notifications',
            type: [NotificationResponseDto],
        }),
        ApiBadRequestResponse({
            description: 'Invalid query parameters',
            schema: {
                example: {
                    statusCode: 400,
                    message:
                        "Invalid 'date' filter. Use: all, today, this-week, this-month",
                    error: 'Bad Request',
                },
            },
        }),
    );
}

export function ApiDocsMarkNotificationAsRead() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Mark a notification as read',
            description:
                'Marks a single notification as read by its ID for the authenticated user.',
        }),
        ApiResponse({
            status: 200,
            description: 'Notification marked as read successfully',
            type: NotificationResponseDto,
        }),
        ApiNotFoundResponse({
            description: 'Notification not found',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Notification not found',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsMarkNotificationsAsReadInBulk() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Mark multiple notifications as read',
            description:
                'Marks multiple notifications as read using an array of notification IDs.',
        }),
        ApiBody({ type: MarkAsReadDto }),
        ApiResponse({
            status: 200,
            description: 'Bulk update result',
            schema: {
                example: {
                    message: 'Successfully marked 3 notification(s) as read',
                    updatedCount: 3,
                },
            },
        }),
        ApiBadRequestResponse({
            description: 'No notification IDs provided',
            schema: {
                example: {
                    statusCode: 403,
                    message: 'No notification IDs provided',
                    error: 'Forbidden',
                },
            },
        }),
        ApiNotFoundResponse({
            description: 'Notifications not found for the user',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'No valid notifications found for this user',
                    error: 'Not Found',
                },
            },
        }),
    );
}

export function ApiDocsNotificationStream() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Stream live notifications (SSE)',
            description:
                'Provides a real-time stream of notifications for the authenticated user via Server-Sent Events.',
        }),
        ApiResponse({
            status: 200,
            description: 'Stream started successfully',
            schema: {
                example: {
                    data: '{"notificationId":"uuid","title":"New Message","content":"You have a new message","sender":{"userId":"uuid","name":"John Doe"},"receiver":{"userId":"uuid","name":"Jane Doe"},"notificationType":"NEW_MESSAGE","isRead":false,"createdAt":"2025-01-01T00:00:00.000Z"}',
                },
            },
        }),
    );
}
