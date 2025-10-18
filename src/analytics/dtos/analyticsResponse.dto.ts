import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { ItemType } from '@prisma/client';
import { SupplierReviewResponseDto } from 'src/review/dtos/reviewResponse.dto';

export class RevenueByMonthResponseDTO {
    @ApiProperty({
        description:
            'Month name for which the revenue and orders are calculated, e.g., "July", "August", "September".',
        example: 'July',
    })
    month: string;

    @ApiProperty({
        description: 'Total number of orders in this month.',
        example: 120,
    })
    totalOrders: number;

    @ApiProperty({
        description: 'Revenue generated from orders only in this month.',
        example: 5000,
    })
    orderRevenue: number;

    @ApiProperty({
        description:
            'Total revenue including orders, invoices, and any other sources for this month.',
        example: 7500,
    })
    totalRevenue: number;
}

export class TopItemResponseDTO {
    @ApiProperty({
        description: 'Unique identifier of the product or service.',
        example: 'abc123',
    })
    itemId: string;

    @ApiProperty({
        description: 'Name of the product or service.',
        example: 'Premium Service',
    })
    name: string;

    @ApiProperty({
        description: 'Type of the item, either PRODUCT or SERVICE.',
        enum: ItemType,
        example: ItemType.PRODUCT,
    })
    type: ItemType;

    @ApiProperty({
        description: 'Number of times this item was purchase.',
        example: 35,
    })
    paidCount: number;

    @ApiPropertyOptional({
        description:
            'Number of times this item was wish-listed, only returned for subscribed suppliers.',
        example: 20,
    })
    wishlistCount?: number;
}

export class TopItemsResponseDTO {
    @ApiProperty({
        description:
            'Array of the most ordered items (products or services) for the supplier.',
        type: [TopItemResponseDTO],
    })
    mostOrdered: TopItemResponseDTO[];

    @ApiPropertyOptional({
        description:
            'Array of the most wish-listed items, returned only if the supplier is subscribed.',
        type: [TopItemResponseDTO],
    })
    mostWishlisted?: TopItemResponseDTO[];
}

export class OverallReviewsResponseDTO {
    @ApiProperty({
        description:
            'Average star rating of the supplier based on all received reviews.',
        example: 4.5,
    })
    averageStars: number;

    @ApiProperty({
        description: 'Total number of reviews the supplier has received.',
        example: 120,
    })
    totalReviews: number;
}

export class ReviewsResponseDTO {
    @ApiProperty({
        description: 'Overall reviews summary for the supplier.',
        type: OverallReviewsResponseDTO,
    })
    overallRating: OverallReviewsResponseDTO;

    @ApiProperty({
        description:
            'Recent reviews received by the supplier in the past three months.',
        type: [SupplierReviewResponseDto],
    })
    recentReviews: SupplierReviewResponseDto[];
}

export class AnalyticsResponseDTO {
    @ApiProperty({
        description:
            'Revenue and orders data per month for the past three months.',
        type: [RevenueByMonthResponseDTO],
    })
    totalRevenue: RevenueByMonthResponseDTO[];

    @ApiPropertyOptional({
        description:
            'Revenue from orders only per month, optional if total revenue already includes all sources.',
        type: [RevenueByMonthResponseDTO],
    })
    totalOrderSales?: RevenueByMonthResponseDTO[];

    @ApiProperty({
        description: 'Top products and services insights for the supplier.',
        type: TopItemsResponseDTO,
    })
    topItems: TopItemsResponseDTO;

    @ApiProperty({
        description: 'Supplier reviews and ratings data.',
        type: ReviewsResponseDTO,
    })
    reviews: ReviewsResponseDTO;
}
