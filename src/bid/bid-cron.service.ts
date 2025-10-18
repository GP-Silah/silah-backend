import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { PrismaService } from 'src/prisma/prisma.service';
import {
    BidExpectedResponseTime,
    BidStatus,
    NotificationEntityType,
    NotificationType,
    OfferStatus,
    PreInvoiceStatus,
} from '@prisma/client';
import { addWeeks, isAfter } from 'date-fns';
import { NotificationService } from 'src/notification/notification.service';

@Injectable()
export class BidCronService {
    private readonly logger = new Logger(BidCronService.name);

    constructor(
        private readonly prisma: PrismaService,
        private readonly notificationService: NotificationService,
    ) {}

    /**
     * Helper: map expected response time enum -> number of weeks
     */
    private getWeeksForResponseTime(
        enumValue: BidExpectedResponseTime,
    ): number {
        const map: Record<BidExpectedResponseTime, number> = {
            ONE_WEEK: 1,
            TWO_WEEKS: 2,
            FOUR_WEEKS: 4,
            SIX_WEEKS: 6,
        };
        return map[enumValue] ?? 1; // fallback default
    }

    @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
    async closeExpiredBids() {
        this.logger.log('Running daily bid expiration check...');

        const now = new Date();

        // 1. Get all open bids
        const openBids = await this.prisma.bid.findMany({
            where: { status: BidStatus.OPEN },
            include: { offers: true, buyer: true },
        });

        let closedCount = 0;

        for (const bid of openBids) {
            const weeks = this.getWeeksForResponseTime(
                bid.expectedResponseTime,
            );
            const expirationDate = addWeeks(bid.createdAt, weeks);

            if (isAfter(now, expirationDate)) {
                closedCount++;

                // 2. Close the bid
                await this.prisma.bid.update({
                    where: { id: bid.id },
                    data: { status: BidStatus.CLOSED },
                });

                // 3. Decline all offers
                await this.prisma.offer.updateMany({
                    where: { bidId: bid.id },
                    data: {
                        status: OfferStatus.DECLINED,
                    },
                });

                // 4. Fail related pre-invoices
                await this.prisma.preInvoice.updateMany({
                    where: {
                        offer: { bidId: bid.id },
                    },
                    data: { status: PreInvoiceStatus.FAILED },
                });

                // 5. Send a notification for the suppliers
                for (const offer of bid.offers) {
                    const updatedOffer = await this.prisma.offer.update({
                        where: { id: offer.id },
                        data: { status: OfferStatus.DECLINED },
                        include: { supplier: true },
                    });

                    // Send notification
                    await this.notificationService.createNotification({
                        senderUserId: bid.buyer.userId,
                        receiverUserId: updatedOffer.supplier.userId,
                        type: NotificationType.BID_STATUS_CHANGED,
                        title: 'Offer Status Changed!',
                        content: `Your offer ${updatedOffer.id} got ${updatedOffer.status.toLowerCase()}`,
                        entityId: updatedOffer.id,
                        entityType: NotificationEntityType.OFFER,
                    });
                }

                this.logger.warn(
                    `Closed bid "${bid.id}" (expired after ${weeks} week(s)). Declined ${bid.offers.length} offers.`,
                );
            }
        }

        this.logger.log(
            closedCount > 0
                ? `Closed ${closedCount} expired bids.`
                : 'No expired bids found.',
        );
    }
}
