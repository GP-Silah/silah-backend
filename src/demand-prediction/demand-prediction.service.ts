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
            return new NotFoundException('Supplier not found');
        }
        const product = await this.prisma.product.findFirst({
            where: { id: productId, supplierId: supplier.id, isDeleted: false }, //? make it only for products that have past sales
        });
        if (!product) {
            return new NotFoundException('Product not found');
        }
        // get sales data for the product
        // send axios req to FastAPI backend
        // return res from FastAPI
    }
}
