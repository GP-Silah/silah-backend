import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { ReviewService } from 'src/review/review.service';
import { subMonths, startOfMonth, endOfMonth } from 'date-fns';
import {
    AnalyticsResponseDTO,
    RevenueByMonthResponseDTO,
    TopItemsResponseDTO,
    ReviewsResponseDTO,
    OverallReviewsResponseDTO,
    TopItemResponseDTO,
} from './dtos/analyticsResponse.dto';
import { InvoiceStatus, ItemType, SupplierPlan } from '@prisma/client';

@Injectable()
export class AnalyticsService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly reviewService: ReviewService,
    ) {}

    async getMyAnalytics(userId: string): Promise<AnalyticsResponseDTO> {
        const supplier = await this.prisma.supplier.findFirst({
            where: { userId, isDeleted: false },
            include: { user: true },
        });
        if (!supplier) {
            throw new NotFoundException('Supplier not found');
        }

        const now = new Date();
        const currentMonthStart = startOfMonth(now);

        // Past 3 full months (excluding current month)
        const monthRanges = [1, 2, 3].map((monthsAgo) => {
            const start = startOfMonth(subMonths(currentMonthStart, monthsAgo));
            const end = endOfMonth(subMonths(currentMonthStart, monthsAgo));
            return { start, end };
        });

        // revenue per each of the 3 months (orders + fully paid invoices)
        const totalRevenue: RevenueByMonthResponseDTO[] = await Promise.all(
            monthRanges.map(async ({ start, end }) => {
                const orders = await this.prisma.order.aggregate({
                    where: {
                        supplierId: supplier.id,
                        createdAt: { gte: start, lte: end },
                    },
                    _sum: { finalPrice: true },
                    _count: { id: true },
                });

                const invoicesRaw = await this.prisma.invoice.findMany({
                    where: {
                        supplierId: supplier.id,
                        status: InvoiceStatus.FULLY_PAID,
                        createdAt: { gte: start, lte: end },
                    },
                    select: { amount: true },
                });

                const invoicesSum = invoicesRaw.reduce(
                    (sum, inv) => sum + (inv.amount ?? 0),
                    0,
                );

                return {
                    month: start.toLocaleString('default', { month: 'long' }),
                    totalOrders: orders._count.id,
                    orderRevenue: orders._sum.finalPrice ?? 0,
                    totalRevenue: (orders._sum.finalPrice ?? 0) + invoicesSum,
                };
            }),
        );

        // ----- Top items: use the exact same 3-month window (start ... end) -----
        const startRange = monthRanges[2].start; // earliest of the 3 months
        const endRange = monthRanges[0].end; // latest of the 3 months

        // products list (basic info)
        const products = await this.prisma.product.findMany({
            where: { supplierId: supplier.id, isDeleted: false },
            select: { id: true, name: true, wishlistCount: true },
        });

        // compute paid counts for products (orders in window)
        const productCounts = await Promise.all(
            products.map(async (p) => {
                const paidCount = await this.prisma.orderItem.count({
                    where: {
                        productId: p.id,
                        order: {
                            supplierId: supplier.id,
                            createdAt: { gte: startRange, lte: endRange },
                        },
                    },
                });

                return {
                    itemId: p.id,
                    name: p.name,
                    type: ItemType.PRODUCT,
                    paidCount,
                    wishlistCount:
                        supplier.plan === SupplierPlan.PREMIUM
                            ? p.wishlistCount
                            : undefined,
                } as TopItemResponseDTO;
            }),
        );

        // services list (basic info)
        const services = await this.prisma.service.findMany({
            where: { supplierId: supplier.id, isDeleted: false },
            select: { id: true, name: true, wishlistCount: true },
        });

        // compute paid counts for services (invoice items from fully paid invoices in window)
        const serviceCounts = await Promise.all(
            services.map(async (s) => {
                const paidCount = await this.prisma.invoiceItem.count({
                    where: {
                        // use the actual FK name in your schema (seems to be relatedServiceId in your schema)
                        relatedServiceId: s.id,
                        invoice: {
                            supplierId: supplier.id,
                            status: InvoiceStatus.FULLY_PAID,
                            createdAt: { gte: startRange, lte: endRange },
                        },
                    },
                });

                return {
                    itemId: s.id,
                    name: s.name,
                    type: ItemType.SERVICE,
                    paidCount,
                    wishlistCount:
                        supplier.plan === SupplierPlan.PREMIUM
                            ? s.wishlistCount
                            : undefined,
                } as TopItemResponseDTO;
            }),
        );

        // combine and drop zero-paid items, then sort & slice
        const combined = [...productCounts, ...serviceCounts];

        // filter out items with paidCount === 0 (they should not appear)
        const nonZero = combined.filter((it) => (it.paidCount ?? 0) > 0);

        const topItemsMapped: TopItemResponseDTO[] = nonZero;

        const topItems: TopItemsResponseDTO = {
            mostOrdered: [...topItemsMapped]
                .sort((a, b) => b.paidCount - a.paidCount)
                .slice(0, 5),
            mostWishlisted:
                supplier.plan === SupplierPlan.PREMIUM
                    ? [...topItemsMapped]
                          .sort(
                              (a, b) =>
                                  (b.wishlistCount ?? 0) -
                                  (a.wishlistCount ?? 0),
                          )
                          .slice(0, 5)
                    : undefined,
        };

        // ---------------------------
        // Reviews (past 3 months start)
        // ---------------------------
        const reviewEntities = await this.prisma.review.findMany({
            where: {
                supplierId: supplier.id,
                createdAt: { gte: startRange, lte: endRange },
            },
            include: {
                buyer: { include: { user: true } },
                supplier: { include: { user: true } },
                itemsReview: true,
            },
        });

        const recentReviews = await Promise.all(
            reviewEntities.map((review) =>
                this.reviewService.toSupplierReviewResponseDto(
                    review,
                    supplier,
                ),
            ),
        );

        const totalStars = reviewEntities.reduce(
            (sum, r) => sum + r.supplierRating,
            0,
        );
        const overallRating: OverallReviewsResponseDTO = {
            averageStars: reviewEntities.length
                ? totalStars / reviewEntities.length
                : 0,
            totalReviews: reviewEntities.length,
        };

        const reviews: ReviewsResponseDTO = {
            overallRating,
            recentReviews,
        };

        return {
            totalRevenue,
            topItems,
            reviews,
        };
    }
}
