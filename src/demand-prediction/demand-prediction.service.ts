import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class DemandPredictionService {
    constructor(private readonly prisma: PrismaService) {}

    async getPredictionForProduct(productId: string, userId: string) {
        const supplier = await this.prisma.supplier.findUnique({
            where: { userId },
            include: { user: true },
        });
        if (!supplier) {
            throw new NotFoundException('Supplier not found');
        }
        const product = await this.prisma.product.findFirst({
            where: { id: productId, supplierId: supplier.id, isDeleted: false }, //? make it only for products that have past sales < 50 == send it warn
        });
        if (!product) {
            throw new NotFoundException('Product not found');
        }
        const allPastSales = await this.getDailySalesForProduct(product.id);
        return allPastSales;
        // send axios req to FastAPI backend
        // return res from FastAPI
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
        AND o."status" = 'COMPLETED'
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
