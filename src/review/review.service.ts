import {
    BadRequestException,
    ForbiddenException,
    Injectable,
    InternalServerErrorException,
    NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import {
    ItemReviewResponseDto,
    ReviewResponseDto,
    SupplierReviewResponseDto,
} from './dtos/reviewResponse.dto';
import { BuyerService } from 'src/buyer/buyer.service';
import { SupplierService } from 'src/supplier/supplier.service';
import { ProductService } from 'src/product/product.service';
import { ServiceService } from 'src/service/service.service';
import { CreateReviewDto } from './dtos/createReview.dto';
import {
    InvoiceStatus,
    NotificationEntityType,
    NotificationType,
    OrderStatus,
} from '@prisma/client';
import { NotificationService } from 'src/notification/notification.service';
import { TranslationService } from 'src/translation/translation.service';

@Injectable()
export class ReviewService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly buyerService: BuyerService,
        private readonly supplierService: SupplierService,
        private readonly productService: ProductService,
        private readonly serviceService: ServiceService,
        private readonly notificationService: NotificationService,
        private readonly translationService: TranslationService,
    ) {}

    /** Helper: fetch user's preferred language */
    async getUserLanguage(userId: string): Promise<'ar' | 'en' | null> {
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
            select: { preferredLanguage: true },
        });
        const lang = user?.preferredLanguage?.toLowerCase();
        return lang === 'ar' || lang === 'en' ? lang : null;
    }

    private async toItemReviewResponseDto(
        itemReviewEntity: any,
        targetLang?: 'ar' | 'en',
    ): Promise<ItemReviewResponseDto> {
        return {
            itemReviewId: itemReviewEntity.id,
            reviewId: itemReviewEntity.reviewId,
            orderItemReview: itemReviewEntity.orderItem
                ? {
                      orderItemId: itemReviewEntity.orderItem.id,
                      product: itemReviewEntity.orderItem.product
                          ? await this.productService.toProductResponseDto(
                                itemReviewEntity.orderItem.product,
                            )
                          : undefined,
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
            writtenReviewOfItem: targetLang
                ? await this.translationService.translateText(
                      itemReviewEntity.writtenReviewOfItem,
                      targetLang,
                  )
                : itemReviewEntity.writtenReviewOfItem,
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

    async getSupplierReviews(
        supplierId: string,
        targetLang?: 'ar' | 'en',
    ): Promise<SupplierReviewResponseDto[]> {
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

        return Promise.all(
            reviews.map(async (review) => {
                const dto: SupplierReviewResponseDto = {
                    reviewId: review.id,
                    orderId: review.orderId ?? undefined,
                    invoiceId: review.invoiceId ?? undefined,
                    buyerId: review.buyerId ?? undefined,
                    supplierRating: review.supplierRating,
                    writtenReviewOfSupplier:
                        targetLang && review.writtenReviewOfSupplier
                            ? await this.translationService.translateText(
                                  review.writtenReviewOfSupplier,
                                  targetLang,
                              )
                            : (review.writtenReviewOfSupplier ?? undefined),
                    createdAt: review.createdAt,
                    supplier: await this.supplierService.toSupplierResponseDTO(
                        supplier.user,
                        supplier,
                    ),
                };
                return dto;
            }),
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
                        orderItem: {
                            include: {
                                product: { include: { category: true } },
                            },
                        },
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

    async getItemReviews(
        itemId: string,
        targetLang?: 'ar' | 'en',
    ): Promise<ItemReviewResponseDto[]> {
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
                orderItem: {
                    include: { product: { include: { category: true } } },
                },
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
            itemReviews.map((item) =>
                this.toItemReviewResponseDto(item, targetLang),
            ),
        );
    }

    async createReview(
        userId: string,
        id: string,
        dto: CreateReviewDto,
    ): Promise<ReviewResponseDto> {
        // Identify if order or invoice. NOTE: we only include buyer & supplier here.
        const order = await this.prisma.order.findUnique({
            where: { id },
            include: {
                buyer: { include: { user: true } },
                supplier: { include: { user: true } },
            },
        });

        const invoice = await this.prisma.invoice.findUnique({
            where: { id },
            include: {
                buyer: { include: { user: true } },
                supplier: { include: { user: true } },
            },
        });

        if (!order && !invoice)
            throw new NotFoundException(
                `No order or invoice found with ID: ${id}`,
            );

        const buyer = order ? order.buyer : invoice!.buyer;
        const supplier = order ? order.supplier : invoice!.supplier;

        // Validate the request user is the buyer who made the order/invoice
        const toValidateUser = await this.prisma.user.findUnique({
            where: { id: userId },
            include: { buyer: true },
        });

        if (!buyer || !supplier) {
            throw new NotFoundException('Buyer or Supplier not found');
        }
        // compare ids (not object references)
        if (
            !toValidateUser ||
            !toValidateUser.buyer ||
            toValidateUser.buyer.id !== buyer.id
        ) {
            throw new ForbiddenException(
                "You can't write a review to an order or an invoice you haven't made",
            );
        }

        if (order) {
            const validateReview = await this.prisma.review.findFirst({
                where: { orderId: order.id },
            });
            if (validateReview) {
                throw new BadRequestException(
                    `You already reviewd order with ID: ${order.id}`,
                );
            }

            if (order.status !== OrderStatus.COMPLETED) {
                throw new BadRequestException(
                    `Order must be marked as completed before writting a review. Current status: ${order.status}`,
                );
            }

            for (const itemDto of dto.itemsReview || []) {
                // order-based item review -> expect orderItemId
                if (!itemDto.orderItemId) {
                    throw new BadRequestException(
                        'orderItemId is required for order-based reviews',
                    );
                }

                // Directly fetch the OrderItem
                const orderItem = await this.prisma.orderItem.findUnique({
                    where: { id: itemDto.orderItemId },
                    include: { product: true },
                });

                if (!orderItem) {
                    throw new InternalServerErrorException(
                        `OrderItem ${itemDto.orderItemId} not found`,
                    );
                }

                if (orderItem.orderId !== order.id) {
                    throw new ForbiddenException(
                        `OrderItem ${orderItem.id} does not belong to order ${order.id}`,
                    );
                }
            }
        }
        if (invoice) {
            const validateReview = await this.prisma.review.findFirst({
                where: { invoiceId: invoice.id },
            });
            if (validateReview) {
                throw new BadRequestException(
                    `You already reviewd invoice with ID: ${invoice.id}`,
                );
            }

            if (invoice.status !== InvoiceStatus.FULLY_PAID) {
                throw new BadRequestException(
                    `Invoice must be fully paid before writting a review. Current status: ${invoice.status}`,
                );
            }

            for (const itemDto of dto.itemsReview || []) {
                // invoice-based
                if (!itemDto.invoiceItemId) {
                    throw new BadRequestException(
                        'invoiceItemId is required for invoice-based reviews',
                    );
                }

                const invoiceItem = await this.prisma.invoiceItem.findUnique({
                    where: { id: itemDto.invoiceItemId },
                });
                if (!invoiceItem) {
                    throw new InternalServerErrorException(
                        `Invoice Item not found for invoice ${invoice!.id}`,
                    );
                }

                if (invoiceItem.relatedProductId) {
                    const product = await this.prisma.product.findUnique({
                        where: { id: invoiceItem!.relatedProductId },
                    });
                    if (!product) {
                        throw new InternalServerErrorException(
                            `Related Product not found for invoice ${invoice!.id}`,
                        );
                    }
                }

                if (invoiceItem.relatedServiceId) {
                    const service = await this.prisma.service.findUnique({
                        where: { id: invoiceItem.relatedServiceId },
                    });
                    if (!service) {
                        throw new InternalServerErrorException(
                            `Related Service not found for invoice ${invoice!.id}`,
                        );
                    }
                }
            }
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
        for (const itemDto of dto.itemsReview || []) {
            if (order) {
                // Directly fetch the OrderItem
                const orderItem = await this.prisma.orderItem.findUnique({
                    where: { id: itemDto.orderItemId },
                    include: { product: true },
                });

                const itemReview = await this.prisma.itemReview.create({
                    data: {
                        reviewId: review.id,
                        buyerId: buyer.id,
                        itemRating: itemDto.itemRating,
                        writtenReviewOfItem: itemDto.writtenReviewOfItem,
                        orderItemId: orderItem!.id,
                    },
                });

                // Update Product rating if this item has a product
                if (orderItem!.product) {
                    const product = orderItem!.product;
                    // compute new average
                    const newCount = product.ratingsCount + 1;
                    const newAvg =
                        (product.avgRating * product.ratingsCount +
                            itemDto.itemRating) /
                        newCount;

                    await this.prisma.product.update({
                        where: { id: product.id },
                        data: {
                            ratingsCount: { increment: 1 },
                            avgRating: newAvg,
                        },
                    });
                }
            } else {
                const invoiceItem = await this.prisma.invoiceItem.findUnique({
                    where: { id: itemDto.invoiceItemId },
                });

                const itemReview = await this.prisma.itemReview.create({
                    data: {
                        reviewId: review.id,
                        buyerId: buyer.id,
                        itemRating: itemDto.itemRating,
                        writtenReviewOfItem: itemDto.writtenReviewOfItem,
                        invoiceItemId: invoiceItem!.id,
                    },
                });

                // Update product/service ratings for invoice item
                if (invoiceItem!.relatedProductId) {
                    const product = await this.prisma.product.findUnique({
                        where: { id: invoiceItem!.relatedProductId },
                    });
                    const newCount = product!.ratingsCount + 1;
                    const newAvg =
                        (product!.avgRating * product!.ratingsCount +
                            itemDto.itemRating) /
                        newCount;

                    await this.prisma.product.update({
                        where: { id: product!.id },
                        data: {
                            ratingsCount: { increment: 1 },
                            avgRating: newAvg,
                        },
                    });
                }
                if (invoiceItem!.relatedServiceId) {
                    const service = await this.prisma.service.findUnique({
                        where: { id: invoiceItem!.relatedServiceId },
                    });
                    const newCount = service!.ratingsCount + 1;
                    const newAvg =
                        (service!.avgRating * service!.ratingsCount +
                            itemDto.itemRating) /
                        newCount;

                    await this.prisma.service.update({
                        where: { id: service!.id },
                        data: {
                            ratingsCount: { increment: 1 },
                            avgRating: newAvg,
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

        // Re-fetch the review with items (include product categories)
        const reviewWithItems = await this.prisma.review.findUnique({
            where: { id: review.id },
            include: {
                buyer: { include: { user: true } },
                supplier: { include: { user: true } },
                itemsReview: {
                    include: {
                        orderItem: {
                            include: {
                                product: { include: { category: true } },
                            },
                        },
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

        if (order) {
            // Send a notification for the supplier
            await this.notificationService.createNotification({
                senderUserId: buyer.userId,
                receiverUserId: supplier.userId,
                type: NotificationType.NEW_REVIEW,
                title: 'New Review!',
                content: `You have received a new review from ${buyer.user.name}`,
                entityId: order.id,
                entityType: NotificationEntityType.ORDER,
            });
        }
        if (invoice) {
            // Send a notification for the supplier
            await this.notificationService.createNotification({
                senderUserId: buyer.userId,
                receiverUserId: supplier.userId,
                type: NotificationType.NEW_REVIEW,
                title: 'New Review!',
                content: `You have received a new review from ${buyer.user.name}`,
                entityId: invoice.id,
                entityType: NotificationEntityType.INVOICE,
            });
        }

        return this.toReviewResponseDto(reviewWithItems);
    }
}
