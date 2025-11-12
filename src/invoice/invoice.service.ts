import { TapPaymentsService } from 'src/tap-payments/tap-payments.service';
import {
    BadRequestException,
    ForbiddenException,
    Injectable,
    InternalServerErrorException,
    NotFoundException,
} from '@nestjs/common';
import {
    InvoiceStatus,
    InvoiceTermsOfPayment,
    NotificationEntityType,
    NotificationType,
    UserRole,
} from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';
import {
    InvoiceItemResponseDto,
    InvoiceResponseDto,
    PreInvoiceResponseDto,
} from './dtos/invoiceResponse.dto';
import { BuyerService } from 'src/buyer/buyer.service';
import { SupplierService } from 'src/supplier/supplier.service';
import { ProductService } from 'src/product/product.service';
import { ServiceService } from 'src/service/service.service';
import { CreateInvoiceDto } from './dtos/createInvoice.dto';
import { NotificationService } from 'src/notification/notification.service';
import { OfferService } from 'src/offer/offer.service';
import { GroupPurchaseService } from 'src/group-purchase/group-purchase.service';
import { PayInvoiceDto } from './dtos/payInvoice.dto';

@Injectable()
export class InvoiceService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly buyerService: BuyerService,
        private readonly supplierService: SupplierService,
        private readonly productService: ProductService,
        private readonly serviceService: ServiceService,
        private readonly tapPaymentService: TapPaymentsService,
        private readonly notificationService: NotificationService,
        private readonly offerService: OfferService,
        private readonly groupPurchaseService: GroupPurchaseService,
    ) {}

    async toInvoiceResponseDto(
        entity: any,
        type: 'INVOICE' | 'PRE_INVOICE',
    ): Promise<InvoiceResponseDto | PreInvoiceResponseDto> {
        if (type === 'INVOICE') {
            return {
                invoiceId: entity.id,
                type,
                status: entity.status,
                buyer: await this.buyerService.toBuyerResponseDto(
                    entity.buyer.user,
                    entity.buyer,
                ),
                supplier: await this.supplierService.toSupplierResponseDTO(
                    entity.supplier.user,
                    entity.supplier,
                ),
                termsOfPayment: entity.termsOfPayment,
                upfrontAmount: entity.upfrontAmount ?? null,
                tapChargeIdForUpfront: entity.tapChargeIdForUpfront ?? null,
                tapChargeId: entity.tapChargeId ?? null,
                deliveryDate: entity.deliveryDate,
                notesAndTerms: entity.notesAndTerms,
                items: entity.items
                    ? await Promise.all(
                          entity.items.map(
                              async (item: any) =>
                                  ({
                                      invoiceItemId: item.id,
                                      name: item.name,
                                      description: item.description,
                                      agreedDetails: item.agreedDetails,
                                      quantity: item.quantity,
                                      unitPrice: item.unitPrice,
                                      priceBasedQuantity:
                                          item.priceBasedQuantity,
                                      relatedProduct: item.relatedProduct
                                          ? await this.productService.toProductResponseDto(
                                                item.relatedProduct,
                                            )
                                          : null,
                                      relatedService: item.relatedService
                                          ? await this.serviceService.toServiceResponseDto(
                                                item.relatedService,
                                            )
                                          : null,
                                  }) as InvoiceItemResponseDto,
                          ),
                      )
                    : [],
                preInvoice: entity.preInvoice
                    ? await this.toInvoiceResponseDto(
                          entity.preInvoice,
                          'PRE_INVOICE',
                      )
                    : null,
                amount: entity.amount,
                createdAt: entity.createdAt,
            } as InvoiceResponseDto;
        } else if (type === 'PRE_INVOICE') {
            return {
                preInvoiceId: entity.id,
                type,
                status: entity.status,
                buyer: entity.buyer
                    ? await this.buyerService.toBuyerResponseDto(
                          entity.buyer.user,
                          entity.buyer,
                      )
                    : undefined,
                supplier: entity.supplier
                    ? await this.supplierService.toSupplierResponseDTO(
                          entity.supplier.user,
                          entity.supplier,
                      )
                    : undefined,
                product: entity.product
                    ? await this.productService.toProductResponseDto(
                          entity.product,
                      )
                    : undefined,
                offer: entity.offer
                    ? await this.offerService.toOfferResponseDto(entity.offer)
                    : undefined,
                groupPurchaseBuyer: entity.groupPurchaseBuyer
                    ? await this.groupPurchaseService.toGroupPurchaseBuyerResponseDto(
                          entity.groupPurchaseBuyer,
                      )
                    : undefined,
                amount: entity.amount,
                createdAt: entity.createdAt,
            } as PreInvoiceResponseDto;
        } else {
            throw new InternalServerErrorException(
                'Invalid invoice type encountered. Only "INVOICE" and "PRE_INVOICE" are supported.',
            );
        }
    }

    async getMyInvoices(
        userId: string,
        status?: InvoiceStatus,
        showFor?: string,
    ): Promise<(InvoiceResponseDto | PreInvoiceResponseDto)[]> {
        // Find user and their role
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
            include: { buyer: true, supplier: true },
        });
        if (!user) throw new NotFoundException('User not found');

        // Determine base filter
        let invoiceWhere: any = {};
        let preInvoiceWhere: any = {};

        if (user.role === UserRole.BUYER) {
            if (!user.buyer)
                throw new BadRequestException('Buyer account not found');
            invoiceWhere.buyerId = user.buyer.id;
            preInvoiceWhere.buyerId = user.buyer.id;
        } else if (user.role === UserRole.SUPPLIER) {
            if (!user.supplier)
                throw new BadRequestException('Supplier account not found');
            invoiceWhere.supplierId = user.supplier.id;
            preInvoiceWhere.supplierId = user.supplier.id;
        } else {
            throw new BadRequestException('Invalid user role');
        }

        // Apply filters
        if (status) invoiceWhere.status = status;

        if (showFor && showFor !== 'all') {
            const itemCondition = this.buildItemFilter(showFor);
            invoiceWhere.items = itemCondition;
            preInvoiceWhere.items = itemCondition;
        }

        // Fetch both invoices and pre-invoices
        const [invoices, preInvoices] = await Promise.all([
            this.prisma.invoice.findMany({
                where: invoiceWhere,
                include: {
                    buyer: { include: { user: true } },
                    supplier: { include: { user: true } },
                    items: {
                        include: {
                            relatedProduct: {
                                include: {
                                    category: true,
                                    supplier: { include: { user: true } },
                                },
                            },
                            relatedService: {
                                include: {
                                    category: true,
                                    supplier: { include: { user: true } },
                                },
                            },
                        },
                    },
                },
                orderBy: { createdAt: 'desc' },
            }),
            this.prisma.preInvoice.findMany({
                where: preInvoiceWhere,
                include: {
                    buyer: { include: { user: true } },
                    supplier: { include: { user: true } },
                    product: {
                        include: {
                            category: true,
                            supplier: { include: { user: true } },
                        },
                    },
                },
                orderBy: { createdAt: 'desc' },
            }),
        ]);

        // Merge and map
        const all = await Promise.all([
            ...invoices.map((inv) => this.toInvoiceResponseDto(inv, 'INVOICE')),
            ...preInvoices.map((pre) =>
                this.toInvoiceResponseDto(pre, 'PRE_INVOICE'),
            ),
        ]);

        // Sort by date (latest first)
        return all.sort(
            (a, b) =>
                new Date(b.createdAt).getTime() -
                new Date(a.createdAt).getTime(),
        );
    }

    private buildItemFilter(showFor: string) {
        switch (showFor) {
            case 'products':
                return { items: { some: { relatedProductId: { not: null } } } };
            case 'services':
                return { items: { some: { relatedServiceId: { not: null } } } };
            case 'groups':
                return { groupPurchaseBuyerId: { not: null } };
            case 'bids':
                return { offerId: { not: null } };
            default:
                return undefined;
        }
    }

    async getMyInvoiceById(
        userId: string,
        id: string,
    ): Promise<InvoiceResponseDto | PreInvoiceResponseDto> {
        // Find user and determine role
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
            include: { buyer: true, supplier: true },
        });
        if (!user) throw new NotFoundException('User not found');

        let invoiceWhere: any = { id };
        let preInvoiceWhere: any = { id };

        if (user.role === UserRole.BUYER) {
            if (!user.buyer)
                throw new BadRequestException('Buyer account not found');
            invoiceWhere.buyerId = user.buyer.id;
            preInvoiceWhere.buyerId = user.buyer.id;
        } else if (user.role === UserRole.SUPPLIER) {
            if (!user.supplier)
                throw new BadRequestException('Supplier account not found');
            invoiceWhere.supplierId = user.supplier.id;
            preInvoiceWhere.supplierId = user.supplier.id;
        } else {
            throw new BadRequestException('Invalid user role');
        }

        // Try to fetch invoice first
        const invoice = await this.prisma.invoice.findUnique({
            where: invoiceWhere,
            include: {
                buyer: { include: { user: true } },
                supplier: { include: { user: true } },
                items: {
                    include: {
                        relatedProduct: {
                            include: {
                                category: true,
                                supplier: { include: { user: true } },
                            },
                        },
                        relatedService: {
                            include: {
                                category: true,
                                supplier: { include: { user: true } },
                            },
                        },
                    },
                },
            },
        });

        if (invoice) {
            return await this.toInvoiceResponseDto(invoice, 'INVOICE');
        }

        // If no invoice, try pre-invoice
        const preInvoice = await this.prisma.preInvoice.findUnique({
            where: preInvoiceWhere,
            include: {
                buyer: { include: { user: true } },
                supplier: { include: { user: true } },
                product: {
                    include: {
                        category: true,
                        supplier: { include: { user: true } },
                    },
                },
            },
        });

        if (preInvoice) {
            return await this.toInvoiceResponseDto(preInvoice, 'PRE_INVOICE');
        }

        // If neither exists
        throw new NotFoundException(
            'No invoice or pre-invoice found for this ID and user.',
        );
    }

    async createInvoice(dto: CreateInvoiceDto) {
        // Validate buyer & supplier existence
        const [buyer, supplier] = await Promise.all([
            this.prisma.buyer.findUnique({ where: { id: dto.buyerId } }),
            this.prisma.supplier.findUnique({ where: { id: dto.supplierId } }),
        ]);

        if (!buyer) throw new NotFoundException('Buyer not found');
        if (!supplier) throw new NotFoundException('Supplier not found');

        // Prepare invoice items
        const itemsData = await Promise.all(
            dto.items.map(async (item) => {
                let relatedProduct: any = null;
                let relatedService: any = null;

                if (item.relatedProductId) {
                    relatedProduct = await this.prisma.product.findFirst({
                        where: {
                            id: item.relatedProductId,
                            supplierId: supplier.id,
                        },
                    });
                    if (!relatedProduct)
                        throw new BadRequestException(
                            `Product not found: ${item.relatedProductId}`,
                        );
                }

                if (item.relatedServiceId) {
                    relatedService = await this.prisma.service.findFirst({
                        where: {
                            id: item.relatedServiceId,
                            supplierId: supplier.id,
                        },
                    });
                    if (!relatedService)
                        throw new BadRequestException(
                            `Service not found: ${item.relatedServiceId}`,
                        );
                }

                return {
                    name: item.name,
                    description: item.description,
                    agreedDetails: item.agreedDetails,
                    quantity: item.quantity,
                    unitPrice: item.unitPrice,
                    priceBasedQuantity: item.unitPrice * item.quantity,
                    relatedProductId: relatedProduct?.id ?? null,
                    relatedServiceId: relatedService?.id ?? null,
                };
            }),
        );

        // Calculate total amount based on items
        const itemsTotal = itemsData.reduce(
            (sum, item) => sum + item.priceBasedQuantity,
            0,
        );

        const totalAmount = itemsTotal;
        const upfrontAmount = dto.upfrontAmount ?? 0;

        // Validate upfront amount
        if (upfrontAmount > totalAmount) {
            throw new BadRequestException(
                'Upfront amount cannot exceed the total invoice amount.',
            );
        }

        // Business rule: limit upfront %
        const MAX_UPFRONT_PERCENT = 0.3;
        const maxAllowedUpfront = totalAmount * MAX_UPFRONT_PERCENT;

        if (upfrontAmount > maxAllowedUpfront) {
            throw new BadRequestException(
                `Upfront amount cannot exceed ${MAX_UPFRONT_PERCENT * 100}% of total (${maxAllowedUpfront.toFixed(
                    2,
                )}).`,
            );
        }

        // Compute upon-delivery amount
        let uponDeliveryAmount: number;
        if (dto.termsOfPayment === 'FULL') {
            uponDeliveryAmount = totalAmount;
        } else {
            uponDeliveryAmount = totalAmount - upfrontAmount;
        }

        // Final consistency check
        if (uponDeliveryAmount + upfrontAmount !== totalAmount) {
            throw new BadRequestException('Amounts do not add up to total.');
        }

        // Create the invoice
        const invoice = await this.prisma.invoice.create({
            data: {
                buyerId: dto.buyerId,
                supplierId: dto.supplierId,
                deliveryDate: new Date(dto.deliveryDate),
                termsOfPayment: dto.termsOfPayment,
                upfrontAmount: dto.upfrontAmount ?? null,
                uponDeliveryAmount: uponDeliveryAmount,
                notesAndTerms: dto.notesAndTerms ?? null,
                amount: totalAmount,
                items: {
                    create: itemsData,
                },
            },
            include: {
                buyer: { include: { user: true } },
                supplier: { include: { user: true } },
                items: {
                    include: {
                        relatedProduct: {
                            include: {
                                category: true,
                                supplier: { include: { user: true } },
                            },
                        },
                        relatedService: {
                            include: {
                                category: true,
                                supplier: { include: { user: true } },
                            },
                        },
                    },
                },
            },
        });

        // Send a notification for the buyer
        await this.notificationService.createNotification({
            senderUserId: supplier.userId,
            receiverUserId: buyer.userId,
            type: NotificationType.NEW_INVOICE,
            title: 'New Invoice!',
            content: `You have received a new invocie from ${invoice.supplier!.user.businessName}`,
            entityId: invoice.id,
            entityType: NotificationEntityType.INVOICE,
        });

        // Convert to InvoiceResponseDto
        return await this.toInvoiceResponseDto(invoice, 'INVOICE');
    }

    async updateInvoiceStatus(
        userId: string,
        invoiceId: string,
        status: InvoiceStatus,
    ): Promise<InvoiceResponseDto> {
        // Find user
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
            include: { buyer: true },
        });
        if (!user || !user.buyer)
            throw new NotFoundException('User or buyer not found');

        // Fetch the invoice for this buyer
        const invoice = await this.prisma.invoice.findFirst({
            where: {
                id: invoiceId,
                buyerId: user.buyer.id,
            },
        });

        if (!invoice) {
            throw new NotFoundException('Invoice not found for this buyer');
        }

        // Only allow updating PENDING invoices
        if (invoice.status !== InvoiceStatus.PENDING) {
            throw new BadRequestException(
                `Invoice status cannot be updated. Current status: ${invoice.status}`,
            );
        }

        // Update the status
        const updatedInvoice = await this.prisma.invoice.update({
            where: { id: invoiceId },
            data: { status },
            include: {
                buyer: { include: { user: true } },
                supplier: { include: { user: true } },
                items: {
                    include: {
                        relatedProduct: {
                            include: {
                                category: true,
                                supplier: { include: { user: true } },
                            },
                        },
                        relatedService: {
                            include: {
                                category: true,
                                supplier: { include: { user: true } },
                            },
                        },
                    },
                },
            },
        });

        // Send a notification for the supplier
        await this.notificationService.createNotification({
            senderUserId: updatedInvoice.buyer!.userId,
            receiverUserId: updatedInvoice.supplier!.userId,
            type: NotificationType.INVOICE_STATUS_CHANGED,
            title: 'Invoice Status Changed!',
            content: `Invoice from ${updatedInvoice.buyer!.user.name} got ${updatedInvoice.status}`,
            entityId: updatedInvoice.id,
            entityType: NotificationEntityType.INVOICE,
        });

        return (await this.toInvoiceResponseDto(
            updatedInvoice,
            'INVOICE',
        )) as InvoiceResponseDto;
    }

    async payInvoice(userId: string, id: string, dto?: PayInvoiceDto) {
        // --- 1. Verify invoice exists and belongs to the buyer ---
        const invoice = await this.prisma.invoice.findUnique({
            where: { id },
            include: {
                buyer: { include: { user: true, card: true } },
                preInvoice: {
                    include: {
                        product: {
                            include: { supplier: { include: { user: true } } },
                        },
                    },
                },
                items: {
                    include: {
                        relatedProduct: {
                            include: {
                                category: true,
                                supplier: { include: { user: true } },
                            },
                        },
                        relatedService: {
                            include: {
                                category: true,
                                supplier: { include: { user: true } },
                            },
                        },
                    },
                },
            },
        });

        if (!invoice || !invoice.buyer)
            throw new NotFoundException('Invoice not found');
        if (invoice.buyer.userId !== userId)
            throw new ForbiddenException(
                'You are not allowed to pay this invoice',
            );
        if (invoice.status === InvoiceStatus.FULLY_PAID)
            throw new BadRequestException('Invoice already paid');
        if (
            invoice.status !== InvoiceStatus.ACCEPTED &&
            invoice.status !== InvoiceStatus.PARTIALLY_PAID
        ) {
            throw new BadRequestException(
                'Invoice must be accepted or partially paid to proceed with payment',
            );
        }

        const buyer = invoice.buyer;

        // --- 2. Validate buyer payment info ---
        if (!buyer.card)
            throw new BadRequestException('No saved card found for this buyer');
        if (!buyer.user.tapCustomerId)
            throw new BadRequestException('Missing Tap customer ID');

        // --- 3. Calculate totals ---
        let totalAmount = 0;

        if (invoice.preInvoice) {
            // Path 1: upgraded preinvoice
            totalAmount = invoice.preInvoice.amount; // everything is included in the preinvoice
        } else {
            // Path 2: normal invoice (multiple products or services)
            const itemsTotal = invoice.items.reduce((sum, item) => {
                const productPrice = item.relatedProduct
                    ? item.relatedProduct.price * item.quantity
                    : 0;
                const servicePrice = item.relatedService
                    ? item.relatedService.price * item.quantity
                    : 0;
                return sum + productPrice + servicePrice;
            }, 0);

            const deliveryFees = invoice.items.reduce(
                (sum, item) =>
                    sum + (item.relatedProduct?.supplier?.deliveryFees ?? 0),
                0,
            );

            totalAmount = itemsTotal + deliveryFees;
        }

        let charge: any;

        // --- 4. Path 1: Use existing charge if chargeId is provided ---
        if (dto && dto.chargeId) {
            charge = await this.tapPaymentService.getCharge(dto.chargeId);
            await this.tapPaymentService.validateCharge(charge);
            if (!['CAPTURED', 'AUTHORIZED'].includes(charge.status)) {
                throw new BadRequestException(
                    `Charge not successful yet. Status: ${charge.status}`,
                );
            }
        } else {
            // --- 5. Path 2: Create new Tap charge ---
            const token = await this.tapPaymentService.createTokenFromSavedCard(
                buyer.user.tapCustomerId,
                buyer.card.tapCardId,
            );

            let chargeAmount: number;
            if (
                invoice.termsOfPayment === InvoiceTermsOfPayment.PARTIAL &&
                !invoice.tapChargeId
            ) {
                // First payment (upfront)
                if (!invoice.upfrontAmount) {
                    throw new InternalServerErrorException(
                        'Partial payment invoices must have an upfront amount specified.',
                    );
                }
                chargeAmount = invoice.upfrontAmount;
            } else {
                // Final payment (upon delivery) or full invoice
                chargeAmount = invoice.uponDeliveryAmount ?? invoice.amount;
            }

            charge = await this.tapPaymentService.payWithSavedCard(
                buyer.user.tapCustomerId,
                token.id,
                buyer.card.tapCardId,
                chargeAmount,
                dto?.redirectUrl ||
                    `${process.env.FRONTEND_URL}/buyer/payment/callback?type=invoice`,
            );

            // --- 6. Redirect for 3DS if needed ---
            if (charge.status === 'INITIATED' && charge.transaction?.url) {
                return {
                    message: 'Redirect for authentication',
                    redirectUrl: charge.transaction.url,
                    chargeId: charge.id,
                };
            }

            if (!['CAPTURED', 'AUTHORIZED'].includes(charge.status)) {
                throw new BadRequestException(
                    `Payment failed. Charge status: ${charge.status}`,
                );
            }
        }

        // --- 7. Update invoice payment details ---
        await this.prisma.$transaction(async (tx) => {
            let newPaidAmount = 0;
            let remainingAmount = 0;
            let newStatus: InvoiceStatus;

            if (
                invoice.termsOfPayment === InvoiceTermsOfPayment.PARTIAL &&
                !invoice.tapChargeId
            ) {
                // First payment (upfront)
                // Only upfrontAmount is paid; the rest remains
                newPaidAmount = invoice.upfrontAmount!;
                remainingAmount = invoice.amount - newPaidAmount;
                newStatus = InvoiceStatus.PARTIALLY_PAID;
            } else if (
                invoice.termsOfPayment === InvoiceTermsOfPayment.PARTIAL &&
                invoice.tapChargeId
            ) {
                // Second payment (upon delivery)
                // The upfront was already paid, now pay the rest
                newPaidAmount = invoice.amount;
                remainingAmount = 0;
                newStatus = InvoiceStatus.FULLY_PAID;
            } else {
                // Full payment
                // Not partial; single full payment from the beginning
                newPaidAmount = invoice.amount;
                remainingAmount = 0;
                newStatus = InvoiceStatus.FULLY_PAID;
            }

            await tx.invoice.update({
                where: { id: invoice.id },
                data: {
                    status: newStatus,
                    tapChargeId: charge.id,
                },
            });
        });

        // --- 8. Return summary ---
        return {
            message:
                invoice.termsOfPayment === InvoiceTermsOfPayment.PARTIAL &&
                !invoice.tapChargeId
                    ? 'Partial payment was made successfully'
                    : 'Invoice paid successfully',
            tapChargeId: charge.id,
            buyerId: buyer.id,
            invoiceId: invoice.id,
            totalPaid: totalAmount,
            totalAmount: invoice.amount,
        };
    }
}
