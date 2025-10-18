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
import {
    InvoiceStatus,
    InvoiceTermsOfPayment,
    ItemType,
    SupplierPlan,
} from '@prisma/client';

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

        // ---------------------------
        // Revenue per month with partial invoices
        // ---------------------------
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
                        createdAt: { gte: start, lte: end },
                    },
                    select: {
                        status: true,
                        termsOfPayment: true,
                        amount: true,
                        upfrontAmount: true,
                        uponDeliveryAmount: true,
                    },
                });

                const invoicesSum = invoicesRaw.reduce((sum, inv) => {
                    if (
                        inv.termsOfPayment === InvoiceTermsOfPayment.FULL &&
                        inv.status === InvoiceStatus.FULLY_PAID
                    ) {
                        return sum + (inv.amount ?? 0);
                    } else if (
                        inv.termsOfPayment === InvoiceTermsOfPayment.PARTIAL
                    ) {
                        return (
                            sum +
                            (inv.status === InvoiceStatus.FULLY_PAID
                                ? (inv.uponDeliveryAmount ?? 0)
                                : (inv.upfrontAmount ?? 0))
                        );
                    }
                    return sum;
                }, 0);

                return {
                    month: start.toLocaleString('default', { month: 'long' }),
                    totalOrders: orders._count.id,
                    orderRevenue: orders._sum.finalPrice ?? 0,
                    totalRevenue: (orders._sum.finalPrice ?? 0) + invoicesSum,
                };
            }),
        );

        // ---------------------------
        // Top products/services
        // ---------------------------
        const products = await this.prisma.product.findMany({
            where: { supplierId: supplier.id, isDeleted: false },
            select: {
                id: true,
                name: true,
                wishlistCount: true,
                _count: { select: { orderItems: true } },
            },
        });

        const services = await this.prisma.service.findMany({
            where: { supplierId: supplier.id, isDeleted: false },
            select: {
                id: true,
                name: true,
                wishlistCount: true,
                _count: { select: { invoiceItems: true } },
            },
        });

        const topItemsMapped: TopItemResponseDTO[] = [
            ...products.map((p) => ({
                itemId: p.id,
                name: p.name,
                type: ItemType.PRODUCT,
                paidCount: p._count.orderItems,
                wishlistCount:
                    supplier.plan === SupplierPlan.PREMIUM
                        ? p.wishlistCount
                        : undefined,
            })),
            ...services.map((s) => ({
                itemId: s.id,
                name: s.name,
                type: ItemType.SERVICE,
                paidCount: s._count.invoiceItems,
                wishListCount:
                    supplier.plan === SupplierPlan.PREMIUM
                        ? s.wishlistCount
                        : undefined,
            })),
        ];

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
        // Reviews
        // ---------------------------
        const reviewEntities = await this.prisma.review.findMany({
            where: {
                supplierId: supplier.id,
                createdAt: { gte: monthRanges[2].start }, // 3 months ago
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

        // ---------------------------
        // Assemble full analytics
        // ---------------------------
        return {
            totalRevenue,
            topItems,
            reviews,
        };
    }
}
