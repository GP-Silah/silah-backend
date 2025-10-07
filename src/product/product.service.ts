import { SupplierService } from './../supplier/supplier.service';
import {
    BadRequestException,
    Injectable,
    NotFoundException,
} from '@nestjs/common';
import {
    Category,
    ItemType,
    Product,
    Supplier,
    SupplierPlan,
    User,
} from '@prisma/client';
import { ProductResponseDto } from './dtos/productResponse.dto';
import { FileService } from 'src/file/file.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateProductDto } from './dtos/createProduct.dto';
import { UpdateProductDto } from './dtos/updateProduct.dto';
import { TranslationService } from 'src/translation/translation.service';
import { SmartSearchService } from 'src/smart-search/smart-search.service';

@Injectable()
export class ProductService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly fileService: FileService,
        private readonly supplierService: SupplierService,
        private readonly translationService: TranslationService,
        private readonly smartSearchService: SmartSearchService,
    ) {}

    STOCK_THRESHOLDS = {
        VERY_LOW: 5, // less than 5 units → VERY LOW
        LOW: 10, // 5–9 units → LOW
        AVERAGE: 30, // 10–29 units → AVERAGE
        GOOD: Infinity, // 30+ units → GOOD
    };

    private getStockStatus(
        stock: number,
    ): 'VERY LOW' | 'LOW' | 'AVERAGE' | 'GOOD' {
        if (stock < this.STOCK_THRESHOLDS.VERY_LOW) return 'VERY LOW';
        if (stock < this.STOCK_THRESHOLDS.LOW) return 'LOW';
        if (stock < this.STOCK_THRESHOLDS.AVERAGE) return 'AVERAGE';
        return 'GOOD';
    }

    async toProductResponseDto(
        product: Product & {
            supplier?: (Supplier & { user: User }) | null;
            category: Category;
        },
        targetLang?: 'ar' | 'en',
    ): Promise<ProductResponseDto & { targetLang?: string }> {
        // include targetLang in response if translated
        // Supplier DTO
        const supplierDto = product.supplier
            ? await this.supplierService.toSupplierResponseDTO(
                  product.supplier.user,
                  product.supplier,
              )
            : null;

        // Signed URLs
        const imagesFilesUrls = await Promise.all(
            product.imagesFilesNames.map((name) =>
                this.fileService.getFileUrl(name),
            ),
        );

        let name = product.name;
        let description = product.description;

        // Only translate if targetLang is provided
        if (targetLang) {
            name = await this.translationService.translateText(
                product.name,
                targetLang,
            );
            description = await this.translationService.translateText(
                product.description,
                targetLang,
            );
        }

        let wishlistCount: number | undefined = undefined;
        if (product.supplier?.plan === 'PREMIUM') {
            wishlistCount = product.wishlistCount;
        }

        return {
            productId: product.id,
            supplierId: product.supplierId ?? null,
            supplier: supplierDto,
            name,
            description,
            price: product.price,
            stock: product.stock,
            category: {
                id: product.categoryId,
                name: product.category.name,
            },
            imagesFilesNames: product.imagesFilesNames,
            imagesFilesUrls,
            caseQuantity: product.caseQuantity,
            minOrderQuantity: product.minOrderQuantity,
            maxOrderQuantity: product.maxOrderQuantity ?? undefined,
            allowGroupPurchase: product.allowGroupPurchase,
            minGroupOrderQuantity: product.minGroupOrderQuantity ?? undefined,
            groupPurchasePrice: product.groupPurchasePrice ?? undefined,
            groupPurchaseDuration: product.groupPurchaseDuration ?? undefined,
            isPublished: product.isPublished,
            stockStatus: this.getStockStatus(product.stock),
            ...(wishlistCount !== undefined ? { wishlistCount } : {}),
            avgRating: product.avgRating,
            ratingsCount: product.ratingsCount,
            createdAt: product.createdAt,
            updatedAt: product.updatedAt,
            isDeleted: product.isDeleted,
            deletedAt: product.deletedAt ?? undefined,
            ...(targetLang ? { targetLang } : {}), // include targetLang only if translated
        };
    }

    async getAllProducts(
        targetLang: 'ar' | 'en',
        userId?: string,
    ): Promise<ProductResponseDto[]> {
        let isPublishedFilter: boolean | undefined = true; // default for buyers

        if (userId) {
            const user = await this.prisma.user.findUnique({
                where: { id: userId },
                include: { supplier: true, buyer: true },
            });
            if (user?.supplier) {
                isPublishedFilter = undefined; // supplier sees all products
            }
        }

        const products = await this.prisma.product.findMany({
            where: {
                isDeleted: false,
                ...(isPublishedFilter !== undefined
                    ? { isPublished: isPublishedFilter }
                    : {}),
            },
            include: {
                supplier: { include: { user: true } },
                category: true,
            },
        });

        if (userId) {
            const user = await this.prisma.user.findFirst({
                where: { id: userId },
            });
            if (user) {
                const lang = user.preferredLanguage.toLocaleLowerCase();
                if (lang === 'ar' || lang === 'en') {
                    targetLang = lang;
                }
            }
        }

        return await Promise.all(
            products.map((product) =>
                this.toProductResponseDto(product, targetLang),
            ),
        );
    }

    async getProductById(
        productId: string,
        targetLang: 'ar' | 'en',
        userId?: string,
    ): Promise<ProductResponseDto> {
        const product = await this.prisma.product.findUnique({
            where: {
                id: productId,
            },
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

        if (userId) {
            const user = await this.prisma.user.findUnique({
                where: { id: userId },
            });
            if (user) {
                const lang = user.preferredLanguage.toLocaleLowerCase();
                if (lang === 'ar' || lang === 'en') {
                    targetLang = lang;
                }
            }
        }

        return this.toProductResponseDto(product, targetLang);
    }

    async getAllSupplierProducts(
        supplierId: string,
        targetLang: 'ar' | 'en',
        userId?: string,
    ): Promise<ProductResponseDto[]> {
        let isPublishedFilter: boolean | undefined = true; // default for buyers

        if (userId) {
            const user = await this.prisma.user.findUnique({
                where: { id: userId },
                include: { supplier: true, buyer: true },
            });
            if (user?.supplier) {
                isPublishedFilter = undefined; // supplier sees all products
            }
        }

        const products = await this.prisma.product.findMany({
            where: {
                supplierId,
                isDeleted: false,
                ...(isPublishedFilter !== undefined
                    ? { isPublished: isPublishedFilter }
                    : {}),
            },
            include: {
                supplier: { include: { user: true } },
                category: true,
            },
        });

        if (userId) {
            const user = await this.prisma.user.findUnique({
                where: { id: userId },
            });
            if (user) {
                const lang = user.preferredLanguage.toLocaleLowerCase();
                if (lang === 'ar' || lang === 'en') {
                    targetLang = lang;
                }
            }
        }

        return Promise.all(
            products.map((p) => this.toProductResponseDto(p, targetLang)),
        );
    }

    async createProduct(
        userId: string,
        dto: CreateProductDto,
        files: Express.Multer.File[],
    ): Promise<ProductResponseDto> {
        // 1. Check supplier
        const supplier = await this.prisma.supplier.findUnique({
            where: { userId },
        });
        if (!supplier) {
            throw new NotFoundException('Supplier not found');
        }

        // Enforce product limit for BASIC plan
        if (supplier.plan === SupplierPlan.BASIC) {
            const activeProductsCount = await this.prisma.product.count({
                where: {
                    supplierId: supplier.id,
                    isDeleted: false,
                },
            });

            const MAX_BASIC_PRODUCTS = 10;
            if (activeProductsCount >= MAX_BASIC_PRODUCTS) {
                throw new BadRequestException(
                    `Basic plan suppliers can only list up to ${MAX_BASIC_PRODUCTS} products. You already have ${activeProductsCount}.`,
                );
            }
        }

        // 2. Validate image count (1–3)
        if (!files || files.length === 0) {
            throw new BadRequestException(
                'At least one product image is required',
            );
        }
        if (files.length > 3) {
            throw new BadRequestException(
                'A maximum of 3 product images is allowed',
            );
        }

        // 3. Validate category
        const category = await this.prisma.category.findUnique({
            where: { id: dto.categoryId },
        });

        if (!category) {
            throw new NotFoundException('Category not found');
        }

        // Must be a subcategory (has parentCategoryId)
        if (!category.parentCategoryId) {
            throw new BadRequestException(
                'Products must be assigned to a subcategory, not a main category',
            );
        }

        // Must also be for products, not services
        if (category.usedFor !== 'PRODUCT') {
            throw new BadRequestException(
                'This category is not valid for products',
            );
        }

        // 4. Upload images to R2
        const uploadedFileNames = await Promise.all(
            files.map((file) => this.fileService.uploadFile(file)),
        );

        // 5. Create product
        const product = await this.prisma.product.create({
            data: {
                supplierId: supplier.id,
                name: dto.name,
                description: dto.description,
                price: dto.price,
                stock: dto.stock ?? 0,
                categoryId: dto.categoryId,
                imagesFilesNames: uploadedFileNames,
                caseQuantity: dto.caseQuantity ?? 1,
                minOrderQuantity: dto.minOrderQuantity ?? 1,
                maxOrderQuantity: dto.maxOrderQuantity ?? null,
                allowGroupPurchase: dto.allowGroupPurchase ?? false,
                minGroupOrderQuantity: dto.minGroupOrderQuantity ?? null,
                groupPurchasePrice: dto.groupPurchasePrice ?? null,
                groupPurchaseDuration: dto.groupPurchaseDuration ?? null,
                isPublished: dto.isPublished ?? false,
            },
        });

        // 6. Return DTO
        const fullProduct = await this.prisma.product.findUnique({
            where: { id: product.id },
            include: {
                supplier: { include: { user: true } },
                category: true,
            },
        });

        // 7. Generate embedding
        await this.smartSearchService.generateAndStoreEmbedding({
            itemId: fullProduct!.id,
            itemType: ItemType.PRODUCT,
            name: fullProduct!.name,
            description: fullProduct!.description,
            categoryName: fullProduct!.category!.name,
        });

        return this.toProductResponseDto(fullProduct!);
    }

    async duplicateProduct(userId: string, productId: string) {
        // 1. Check supplier
        const supplier = await this.prisma.supplier.findUnique({
            where: { userId },
        });
        if (!supplier) {
            throw new NotFoundException('Supplier not found');
        }

        // 2. Find the original product
        const originalProduct = await this.prisma.product.findUnique({
            where: { id: productId, supplierId: supplier.id },
        });
        if (!originalProduct) {
            throw new NotFoundException('Product not found');
        }

        // 3. Duplicate the product
        const duplicatedProduct = await this.prisma.product.create({
            data: {
                supplierId: supplier.id,
                name: `${originalProduct.name} (Copy)`,
                description: originalProduct.description,
                price: originalProduct.price,
                stock: originalProduct.stock,
                categoryId: originalProduct.categoryId,
                imagesFilesNames: originalProduct.imagesFilesNames,
                caseQuantity: originalProduct.caseQuantity,
                minOrderQuantity: originalProduct.minOrderQuantity,
                maxOrderQuantity: originalProduct.maxOrderQuantity,
                allowGroupPurchase: originalProduct.allowGroupPurchase,
                minGroupOrderQuantity: originalProduct.minGroupOrderQuantity,
                groupPurchasePrice: originalProduct.groupPurchasePrice,
                groupPurchaseDuration: originalProduct.groupPurchaseDuration,
                isPublished: false, // don’t publish a copy by default
            },
        });

        // Query back with relations (require for toProductResponseDto function inputs)
        const fullDuplicatedProduct = await this.prisma.product.findUnique({
            where: { id: duplicatedProduct.id },
            include: {
                supplier: { include: { user: true } },
                category: true,
            },
        });

        // 4. Duplicate embedding
        const originalEmbedding = await this.prisma.itemEmbedding.findUnique({
            where: {
                itemId_itemType: {
                    itemId: originalProduct.id,
                    itemType: ItemType.PRODUCT,
                },
            },
        });

        if (originalEmbedding) {
            await this.prisma.itemEmbedding.create({
                data: {
                    itemId: fullDuplicatedProduct!.id,
                    itemType: ItemType.PRODUCT,
                    embedding: originalEmbedding.embedding,
                },
            });
        }

        return this.toProductResponseDto(fullDuplicatedProduct!);
    }

    // Update product fields only (no images)
    async updateProduct(
        userId: string,
        productId: string,
        dto: UpdateProductDto,
    ) {
        // 1. Check supplier
        const supplier = await this.prisma.supplier.findUnique({
            where: { userId },
        });
        if (!supplier) {
            throw new NotFoundException('Supplier not found');
        }

        // 2. Find product
        const product = await this.prisma.product.findUnique({
            where: { id: productId, supplierId: supplier.id },
        });
        if (!product) {
            throw new NotFoundException('Product not found');
        }

        // 3. If categoryId is updated, validate category
        if (dto.categoryId) {
            const category = await this.prisma.category.findUnique({
                where: { id: dto.categoryId },
            });
            if (!category) {
                throw new NotFoundException('Category not found');
            }
            if (!category.parentCategoryId) {
                throw new BadRequestException(
                    'Products must be assigned to a subcategory, not a main category',
                );
            }
            if (category.usedFor !== 'PRODUCT') {
                throw new BadRequestException(
                    'This category is not valid for products',
                );
            }
        }

        // 4. Update product
        const updatedProduct = await this.prisma.product.update({
            where: { id: product.id },
            data: dto,
        });

        // 5. Query back with relations
        const fullProduct = await this.prisma.product.findUnique({
            where: { id: updatedProduct.id },
            include: {
                supplier: { include: { user: true } },
                category: true,
            },
        });

        // 6. Update embedding
        await this.smartSearchService.generateAndStoreEmbedding({
            itemId: fullProduct!.id,
            itemType: ItemType.PRODUCT,
            name: fullProduct!.name,
            description: fullProduct!.description,
            categoryName: fullProduct!.category!.name,
        });

        return this.toProductResponseDto(fullProduct!);
    }

    async updateProductImages(
        userId: string,
        productId: string,
        file: Express.Multer.File,
    ) {
        // 1. Check supplier
        const supplier = await this.prisma.supplier.findUnique({
            where: { userId },
        });
        if (!supplier) {
            throw new NotFoundException('Supplier not found');
        }

        // 2. Find product
        const product = await this.prisma.product.findUnique({
            where: { id: productId, supplierId: supplier.id, isDeleted: false },
        });
        if (!product) {
            throw new NotFoundException('Product not found');
        }

        // 3. Validate image count (max 3)
        if (product.imagesFilesNames.length >= 3) {
            throw new BadRequestException(
                'A maximum of 3 product images is allowed',
            );
        }

        // 4. Upload new image
        const uploadedFileName = await this.fileService.uploadFile(file);

        // 5. Update product images
        const updatedProduct = await this.prisma.product.update({
            where: { id: product.id },
            data: {
                imagesFilesNames: [
                    ...product.imagesFilesNames,
                    uploadedFileName,
                ],
            },
        });

        // 6. Return DTO
        const fullProduct = await this.prisma.product.findUnique({
            where: { id: updatedProduct.id },
            include: {
                supplier: { include: { user: true } },
                category: true,
            },
        });

        return this.toProductResponseDto(fullProduct!);
    }

    async deleteProductImage(
        userId: string,
        productId: string,
        fileName: string,
    ) {
        // 1. Check supplier
        const supplier = await this.prisma.supplier.findUnique({
            where: { userId },
        });
        if (!supplier) {
            throw new NotFoundException('Supplier not found.');
        }

        // 2. Find the product
        const product = await this.prisma.product.findUnique({
            where: { id: productId, supplierId: supplier.id },
        });
        if (!product) {
            throw new NotFoundException('Product not found.');
        }

        // 3. Check if the image exists in product.imagesFilesNames
        if (!product.imagesFilesNames.includes(fileName)) {
            throw new BadRequestException('Image not found in this product.');
        }

        // 4. Filter out the image
        const updatedImages = product.imagesFilesNames.filter(
            (img) => img !== fileName,
        );

        if (updatedImages.length === 0) {
            throw new BadRequestException(
                'A product must have at least one image.',
            );
        }

        // 5. Update product
        const updatedProduct = await this.prisma.product.update({
            where: { id: product.id },
            data: { imagesFilesNames: updatedImages },
        });

        // Future Work ?: Delete the file from R2 storage
        // 6. Query back full product with relations for DTO
        const fullProduct = await this.prisma.product.findUnique({
            where: { id: updatedProduct.id },
            include: {
                supplier: { include: { user: true } },
                category: true,
            },
        });

        return this.toProductResponseDto(fullProduct!);
    }

    async deleteProduct(userId: string, productId: string) {
        // 1. Check supplier
        const supplier = await this.prisma.supplier.findFirst({
            where: { userId },
        });
        if (!supplier) {
            throw new NotFoundException('Supplier not found');
        }

        // 2. Find the product
        const product = await this.prisma.product.findFirst({
            where: { id: productId, supplierId: supplier.id, isDeleted: false },
        });
        if (!product) {
            throw new NotFoundException('Product not found');
        }

        // 3. Soft-delete
        await this.prisma.product.update({
            where: { id: product.id },
            data: {
                isDeleted: true,
                deletedAt: new Date(),
            },
        });

        // 4. Return message
        return {
            message: 'Product deleted successfully',
        };
    }
}
