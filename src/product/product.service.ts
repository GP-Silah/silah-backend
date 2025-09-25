import { SupplierService } from './../supplier/supplier.service';
import { Injectable, NotFoundException } from '@nestjs/common';
import { Product, Supplier, User } from '@prisma/client';
import { ProductResponseDto } from './dtos/productResponse.dto';
import { FileService } from 'src/file/file.service';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class ProductService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly fileService: FileService,
        private readonly supplierService: SupplierService,
    ) {}

    private async uploadImages() {}

    async toProductResponseDto(product: Product): Promise<ProductResponseDto> {
        // Get supplier (nullable)
        let supplier: (Supplier & { user: User }) | null = null;
        if (product.supplierId) {
            supplier = await this.prisma.supplier.findUnique({
                where: { id: product.supplierId },
                include: { user: true },
            });
        }

        const supplierDto = supplier
            ? await this.supplierService.toSupplierResponseDTO(
                  supplier.user,
                  supplier,
              )
            : null;

        // Get category
        const category = await this.prisma.category.findUnique({
            where: { id: product.categoryId },
        });

        // Get signed URLs
        const imagesFilesUrls = await Promise.all(
            product.imagesFilesNames.map((name) =>
                this.fileService.getFileUrl(name),
            ),
        );

        // Map to DTO, respecting nullable → optional conversion
        return {
            id: product.id,
            supplierId: product.supplierId ?? null,
            supplier: supplierDto,
            name: product.name,
            description: product.description,
            price: product.price,
            stock: product.stock,
            category: { id: product.categoryId, name: category!.name },
            imagesFilesNames: product.imagesFilesNames,
            imagesFilesUrls,
            caseQuantity: product.caseQuantity,
            minOrderQuantity: product.minOrderQuantity,
            maxOrderQuantity: product.maxOrderQuantity ?? undefined, // null -> undefined
            allowGroupPurchase: product.allowGroupPurchase,
            minGroupOrderQuantity: product.minGroupOrderQuantity ?? undefined,
            groupPurchasePrice: product.groupPurchasePrice ?? undefined,
            groupPurchaseDuration: product.groupPurchaseDuration ?? undefined,
            isPublished: product.isPublished,
            wishlistCount: product.wishlistCount,
            avgRating: product.avgRating,
            ratingsCount: product.ratingsCount,
            createdAt: product.createdAt,
            updatedAt: product.updatedAt,
            isDeleted: product.isDeleted,
            deletedAt: product.deletedAt ?? undefined,
        };
    }

    async getAllProducts(): Promise<ProductResponseDto[]> {
        const products = await this.prisma.product.findMany({
            where: { isDeleted: false },
        });
        return await Promise.all(
            products.map((product) => this.toProductResponseDto(product)),
        );
    }

    async getProductById(productId: string): Promise<ProductResponseDto> {
        const product = await this.prisma.product.findUnique({
            where: { id: productId },
            include: {
                supplier: { include: { user: true } },
                category: true,
            },
        });
        if (!product) {
            throw new NotFoundException(
                `Product with id ${productId} not found`,
            );
        }
        return this.toProductResponseDto(product);
    }

    async getAllSupplierProducts(
        supplierId: string,
    ): Promise<ProductResponseDto[]> {
        const products = await this.prisma.product.findMany({
            where: { supplierId, isDeleted: false },
            include: {
                supplier: { include: { user: true } },
                category: true,
            },
        });
        return Promise.all(products.map((p) => this.toProductResponseDto(p)));
    }
    async createProduct() {}

    async duplicateProduct() {}

    async updateProduct() {}

    async deleteProduct() {}
}
