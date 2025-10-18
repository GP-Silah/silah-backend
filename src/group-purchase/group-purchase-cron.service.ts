import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { PrismaService } from 'src/prisma/prisma.service';
import {
    GroupPurchaseStatus,
    NotificationEntityType,
    NotificationType,
    PreInvoiceStatus,
} from '@prisma/client';
import { NotificationService } from 'src/notification/notification.service';

@Injectable()
export class GroupPurchaseCronService {
    private readonly logger = new Logger(GroupPurchaseCronService.name);

    constructor(
        private readonly prisma: PrismaService,
        private readonly notificationService: NotificationService,
    ) {}

    // Run once every midnight
    @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
    async closeExpiredGroupPurchases() {
        this.logger.log('Running daily group purchase check...');

        const now = new Date();

        // 1. Find all group purchases that expired and are still open
        const expiredGroups = await this.prisma.groupPurchase.findMany({
            where: {
                deadline: { lt: now },
                status: GroupPurchaseStatus.OPEN,
            },
            include: {
                joinedBuyers: {
                    include: {
                        buyer: { include: { user: true, card: true } }, // needed to send notification
                    },
                },
                supplier: true,
            },
        });

        if (expiredGroups.length === 0) {
            this.logger.log('No expired open group purchases found.');
            return;
        }

        this.logger.warn(
            `Found ${expiredGroups.length} expired group purchases. Closing them...`,
        );

        // 2. Fail preinvoices and Send notifications
        for (const group of expiredGroups) {
            await this.prisma.groupPurchase.update({
                where: { id: group.id },
                data: { status: GroupPurchaseStatus.CLOSED },
            });

            // Fail related pre-invoices
            await this.prisma.preInvoice.updateMany({
                where: {
                    groupPurchaseBuyer: { groupPurchaseId: group.id },
                    status: PreInvoiceStatus.PENDING,
                },
                data: { status: PreInvoiceStatus.FAILED },
            });

            // Send notifications to all joined buyers
            for (const groupPurchaseBuyer of group.joinedBuyers) {
                await this.notificationService.createNotification({
                    senderUserId: group.supplier.userId,
                    receiverUserId: groupPurchaseBuyer.buyer.userId,
                    type: NotificationType.GROUP_PURCHASE_STATUS_CHANGED,
                    title: 'Group Purchase Status Changed!',
                    content: `The group purchase "${group.id}" has closed. Your pre-invoice was marked as failed because requirements were not met in time.`,
                    entityId: group.id,
                    entityType: NotificationEntityType.GROUP_PURCHASE,
                });
            }

            this.logger.log(
                `Closed group purchase "${group.id}" and notified ${group.joinedBuyers.length} buyers.`,
            );
        }

        this.logger.log('Daily group purchase check completed.');
    }
}
