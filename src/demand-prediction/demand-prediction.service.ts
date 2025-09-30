import {
    HttpException,
    HttpStatus,
    Injectable,
    NotFoundException,
    UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import axios from 'axios';
import { SupplierPlan } from '@prisma/client';
import { DemandPredictionResponseDto } from './dtos/demandPredictionResponse.dto';

@Injectable()
export class DemandPredictionService {
    constructor(private readonly prisma: PrismaService) {}

    async getPredictionForProduct(productId: string, userId: string) {
        const supplier = await this.prisma.supplier.findUnique({
            where: { userId },
            include: { user: true },
        });
        if (!supplier || supplier.isDeleted) {
            throw new NotFoundException('Supplier not found');
        }
        if (supplier.plan === SupplierPlan.BASIC) {
            throw new UnauthorizedException(
                'Upgrade plan to access this feature',
            );
        }
        const product = await this.prisma.product.findFirst({
            where: { id: productId, supplierId: supplier.id, isDeleted: false },
        });
        if (!product) {
            throw new NotFoundException('Product not found');
        }
        const allPastSales = await this.getDailySalesForProduct(product.id);
        // Call FastAPI
        try {
            const response = await axios.post(
                `${process.env.AI_BACKEND_URL}/demand`,
                {
                    product_id: product.id,
                    sales: allPastSales,
                    months: 3, // Predict for next 3 months
                },
            );
            const forecast = response.data;

            // Add a lowAccuracy flag if sales history is small
            const lowAccuracy = allPastSales.length < 50;

            // Stocking recommendation (meaning how much more supplier should stock)
            const currentStock = product.stock ?? 0;
            const totalForecast = forecast.forecast.reduce(
                (sum: number, f: { demand: number }) => sum + f.demand,
                0,
            );
            const recommendedStock = Math.max(totalForecast - currentStock, 0);

            return {
                ...forecast,
                lowAccuracy,
                salesCount: allPastSales.length,
                currentStock,
                totalForecast,
                recommendedStock,
            } as DemandPredictionResponseDto;
        } catch (err: any) {
            console.error('FastAPI request failed:', err.message);
            throw new HttpException(
                'Failed to get prediction from AI backend',
                HttpStatus.BAD_GATEWAY,
            );
        }
    }

    async getDailySalesForProduct(productId: string) {
        // Raw SQL query: group sales by order date (all time)
        const dailySales = await this.prisma.$queryRaw<
            { date: Date; quantity: number }[]
        >`
        SELECT 
        DATE(o."createdAt") AS date,
        SUM(ci."quantity") AS quantity
        FROM "Order" o
        INNER JOIN "Cart" c ON o."cartId" = c."id"
        INNER JOIN "CartBySupplier" cs ON cs."cartId" = c."id"
        INNER JOIN "CartItem" ci ON ci."cartBySupplierId" = cs."id"
        WHERE ci."productId" = ${productId}
        GROUP BY DATE(o."createdAt")
        ORDER BY date ASC;
        `;

        if (dailySales.length === 0) {
            return [];
        }

        // Fill missing days with 0 (from first sale to today)
        const result: { date: string; quantity: number }[] = [];
        const firstDate = new Date(dailySales[0].date); // earliest sale date
        const today = new Date();

        for (
            let d = new Date(firstDate);
            d <= today;
            d.setDate(d.getDate() + 1)
        ) {
            const dayStr = d.toISOString().split('T')[0];
            const entry = dailySales.find(
                (s) => s.date.toISOString().split('T')[0] === dayStr,
            );
            result.push({
                date: dayStr,
                quantity: entry ? Number(entry.quantity) : 0,
            });
        }

        return result;
    }
}
