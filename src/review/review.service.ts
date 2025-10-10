import {
    Injectable,
    InternalServerErrorException,
    NotFoundException,
} from '@nestjs/common';
import { InvoiceService } from 'src/invoice/invoice.service';
import { OrderService } from 'src/order/order.service';
import { PrismaService } from 'src/prisma/prisma.service';
import {
    ItemReviewResponseDto,
    ReviewResponseDto,
} from './dtos/reviewResponse.dto';
import { BuyerService } from 'src/buyer/buyer.service';
import { SupplierService } from 'src/supplier/supplier.service';
import { CartService } from 'src/cart/cart.service';
import { ProductService } from 'src/product/product.service';
import { ServiceService } from 'src/service/service.service';
import { CreateReviewDto } from './dtos/createReview.dto';

@Injectable()
export class ReviewService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly buyerService: BuyerService,
        private readonly supplierService: SupplierService,
        private readonly productService: ProductService,
        private readonly serviceService: ServiceService,
    ) {}

    private async toItemReviewResponseDto(
        itemReviewEntity: any,
    ): Promise<ItemReviewResponseDto> {
        return {
            itemReviewId: itemReviewEntity.id,
            reviewId: itemReviewEntity.reviewId,
            orderItemReview: itemReviewEntity.orderItem
                ? {
                      cartItemId: itemReviewEntity.orderItem.id,
                      productId: itemReviewEntity.orderItem.productId,
                      productName: itemReviewEntity.orderItem.productName,
                  }
                : undefined,
            invoiceItemReview: itemReviewEntity.invoiceItem
                ? {
                      invoiceItemId: itemReviewEntity.invoiceItem.id,
                      name: itemReviewEntity.invoiceItem.name,
                      relatedProduct: itemReviewEntity.invoiceItem
                          .relatedProduct
                          ? await this.productService.toProductResponseDto(
                                itemReviewEntity.invoiceItem.relatedProduct,
                            )
                          : undefined,
                      relatedService: itemReviewEntity.invoiceItem
                          .relatedService
                          ? await this.serviceService.toServiceResponseDto(
                                itemReviewEntity.invoiceItem.relatedService,
                            )
                          : undefined,
                  }
                : undefined,
            buyerId: itemReviewEntity.buyerId,
            itemRating: itemReviewEntity.itemRating,
            writtenReviewOfItem: itemReviewEntity.writtenReviewOfItem,
            createdAt: itemReviewEntity.createdAt,
        };
    }

    private async toReviewResponseDto(
        reviewEntity: any,
    ): Promise<ReviewResponseDto> {
        return {
            reviewId: reviewEntity.id,
            orderId: reviewEntity.orderId ?? undefined,
            invoiceId: reviewEntity.invoiceId ?? undefined,
            buyer: await this.buyerService.toBuyerResponseDto(
                reviewEntity.buyer.user,
                reviewEntity.buyer,
            ),
            supplier: await this.supplierService.toSupplierResponseDTO(
                reviewEntity.supplier.user,
                reviewEntity.supplier,
            ),
            supplierRating: reviewEntity.supplierRating,
            writtenReviewOfSupplier:
                reviewEntity.writtenReviewOfSupplier ?? undefined,
            itemsReview: reviewEntity.itemsReview
                ? await Promise.all(
                      reviewEntity.itemsReview.map((item: any) =>
                          this.toItemReviewResponseDto(item),
                      ),
                  )
                : [],
            createdAt: reviewEntity.createdAt,
        };
    }

    async getSupplierReviews(supplierId: string) {
        const supplier = await this.prisma.supplier.findUnique({
            where: { id: supplierId },
            include: { user: true },
        });
        if (!supplier) {
            throw new NotFoundException(
                `No supplier found with ID: ${supplierId}`,
            );
        }

        // Fetch all reviews for this supplier without item reviews
        const reviews = await this.prisma.review.findMany({
            where: { supplierId },
            include: {
                buyer: {
                    include: {
                        user: true, // needed for buyer DTO
                    },
                },
                supplier: {
                    include: {
                        user: true, // needed for supplier DTO
                    },
                },
            },
            orderBy: {
                createdAt: 'desc', // latest reviews first
            },
        });

        // Map entities to DTOs
        return Promise.all(
            reviews.map(async (review) => ({
                reviewId: review.id,
                orderId: review.orderId ?? undefined,
                invoiceId: review.invoiceId ?? undefined,
                buyerId: review.buyerId ?? undefined,
                supplierRating: review.supplierRating,
                writtenReviewOfSupplier:
                    review.writtenReviewOfSupplier ?? undefined,
                createdAt: review.createdAt,
                supplier: await this.supplierService.toSupplierResponseDTO(
                    supplier.user,
                    supplier,
                ),
            })),
        );
    }

    async getReviewById(reviewId: string): Promise<ReviewResponseDto> {
        // Fetch the review including buyer, supplier, and item reviews
        const review = await this.prisma.review.findUnique({
            where: { id: reviewId },
            include: {
                buyer: { include: { user: true } },
                supplier: { include: { user: true } },
                itemsReview: {
                    include: {
                        orderItem: true,
                        invoiceItem: {
                            include: {
                                relatedProduct: { include: { category: true } },
                                relatedService: { include: { category: true } },
                            },
                        },
                    },
                },
            },
        });

        if (!review) {
            throw new NotFoundException(`No review found with ID: ${reviewId}`);
        }

        // Map to DTO
        return this.toReviewResponseDto(review);
    }

    async getItemReviews(itemId: string): Promise<ItemReviewResponseDto[]> {
        // First, check if the itemId is a product or a service
        const product = await this.prisma.product.findUnique({
            where: { id: itemId },
        });

        const service = !product
            ? await this.prisma.service.findUnique({
                  where: { id: itemId },
              })
            : null;

        if (!product && !service) {
            throw new NotFoundException(
                `No product or service found with ID: ${itemId}`,
            );
        }

        // Fetch item reviews for this product or service
        const itemReviews = await this.prisma.itemReview.findMany({
            where: product
                ? { orderItem: { productId: itemId } }
                : { invoiceItem: { relatedServiceId: itemId } },
            include: {
                orderItem: true,
                invoiceItem: {
                    include: {
                        relatedProduct: { include: { category: true } },
                        relatedService: { include: { category: true } },
                    },
                },
            },
            orderBy: { createdAt: 'desc' },
        });

        return Promise.all(
            itemReviews.map((item) => this.toItemReviewResponseDto(item)),
        );
    }

    async createReview(
        userId: string,
        id: string,
        dto: CreateReviewDto,
    ): Promise<ReviewResponseDto> {
        // Identify if order or invoice
        const order = await this.prisma.order.findUnique({
            where: { id },
            include: {
                buyer: true,
                supplier: true,
                cart: {
                    include: {
                        suppliers: {
                            include: {
                                cartItems: { include: { product: true } },
                            },
                        },
                    },
                },
            },
        });

        const invoice = await this.prisma.invoice.findUnique({
            where: { id },
            include: { buyer: true, supplier: true, items: true },
        });

        if (!order && !invoice)
            throw new NotFoundException(
                `No order or invoice found with ID: ${id}`,
            );

        const buyer = order ? order.buyer : invoice!.buyer;

        const supplier = order ? order.supplier : invoice!.supplier;

        if (!buyer || !supplier) {
            throw new NotFoundException('Buyer or Supplier not found');
        }

        // Create Review
        const review = await this.prisma.review.create({
            data: {
                buyerId: buyer.id,
                supplierId: supplier.id,
                orderId: order?.id,
                invoiceId: invoice?.id,
                supplierRating: dto.supplierRating,
                writtenReviewOfSupplier: dto.writtenReviewOfSupplier,
            },
        });

        // Create Item Reviews
        for (const itemDto of dto.itemsReview) {
            const itemData = order
                ? { orderItemId: itemDto.orderItemId }
                : { invoiceItemId: itemDto.invoiceItemId };

            const itemReview = await this.prisma.itemReview.create({
                data: {
                    reviewId: review.id,
                    buyerId: buyer.id,
                    itemRating: itemDto.itemRating,
                    writtenReviewOfItem: itemDto.writtenReviewOfItem,
                    ...itemData,
                },
            });

            // Update Product/Service rating
            if (order && itemReview.orderItemId) {
                const orderWithCart = await this.prisma.order.findUnique({
                    where: { id: order.id },
                    include: {
                        cart: {
                            include: {
                                suppliers: {
                                    include: {
                                        cartItems: {
                                            include: { product: true },
                                        },
                                    },
                                },
                            },
                        },
                    },
                });

                if (!orderWithCart) {
                    throw new InternalServerErrorException(
                        `Order ${order.id} not found`,
                    );
                }

                // Find the specific CartItem that matches the itemReview
                const foundCartItem = orderWithCart.cart.suppliers
                    .flatMap((s) => s.cartItems)
                    .find((item) => item.id === itemReview.orderItemId);

                if (!foundCartItem) {
                    throw new InternalServerErrorException(
                        `Cart item not found for order ${order.id}`,
                    );
                }

                const product = foundCartItem.product;

                if (!product) {
                    throw new InternalServerErrorException(
                        `Product not found for cart item ${foundCartItem.id}`,
                    );
                }

                await this.prisma.product.update({
                    where: { id: product.id },
                    data: {
                        ratingsCount: { increment: 1 },
                        avgRating:
                            (product.avgRating * product.ratingsCount +
                                itemDto.itemRating) /
                            (product.ratingsCount + 1),
                    },
                });
            } else if (invoice && itemReview.invoiceItemId) {
                const invoiceItem = await this.prisma.invoiceItem.findUnique({
                    where: { id: itemDto.invoiceItemId },
                });
                if (!invoiceItem) {
                    throw new InternalServerErrorException(
                        `Invoice Item not found for invocie ${invoice}`,
                    );
                }
                if (invoiceItem.relatedProductId) {
                    const product = await this.prisma.product.findUnique({
                        where: { id: invoiceItem.relatedProductId },
                    });
                    if (!product) {
                        throw new InternalServerErrorException(
                            `Related Product not found for invoice ${invoice.id}`,
                        );
                    }
                    await this.prisma.product.update({
                        where: { id: product.id },
                        data: {
                            ratingsCount: { increment: 1 },
                            avgRating:
                                (product.avgRating * product.ratingsCount +
                                    itemDto.itemRating) /
                                (product.ratingsCount + 1),
                        },
                    });
                }
                if (invoiceItem.relatedServiceId) {
                    const service = await this.prisma.service.findUnique({
                        where: { id: invoiceItem.relatedServiceId },
                    });
                    if (!service) {
                        throw new InternalServerErrorException(
                            `Related Service not found for invoice ${invoice.id}`,
                        );
                    }
                    await this.prisma.service.update({
                        where: { id: service.id },
                        data: {
                            ratingsCount: { increment: 1 },
                            avgRating:
                                (service.avgRating * service.ratingsCount +
                                    itemDto.itemRating) /
                                (service.ratingsCount + 1),
                        },
                    });
                }
            }
        }

        // Update Supplier rating
        await this.prisma.supplier.update({
            where: { id: supplier.id },
            data: {
                ratingsCount: { increment: 1 },
                avgRating:
                    (supplier.avgRating * supplier.ratingsCount +
                        dto.supplierRating) /
                    (supplier.ratingsCount + 1),
            },
        });

        // Return DTO
        const reviewWithItems = await this.prisma.review.findUnique({
            where: { id: review.id },
            include: {
                buyer: { include: { user: true } },
                supplier: { include: { user: true } },
                itemsReview: {
                    include: {
                        orderItem: true,
                        invoiceItem: {
                            include: {
                                relatedProduct: { include: { category: true } },
                                relatedService: { include: { category: true } },
                            },
                        },
                    },
                },
            },
        });

        return this.toReviewResponseDto(reviewWithItems);
    }
}
