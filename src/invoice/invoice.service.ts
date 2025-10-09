import { TapPaymentsService } from 'src/tap-payments/tap-payments.service';
import {
    BadRequestException,
    Injectable,
    InternalServerErrorException,
    NotFoundException,
} from '@nestjs/common';
import { InvoiceStatus, UserRole } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';
import {
    InvoiceItemDto,
    InvoiceResponseDto,
    PreInvoiceResponseDto,
} from './dtos/invoiceResponse.dto';
import { BuyerService } from 'src/buyer/buyer.service';
import { SupplierService } from 'src/supplier/supplier.service';
import { ProductService } from 'src/product/product.service';
import { ServiceService } from 'src/service/service.service';
import { CreateInvoiceDto } from './dtos/createInvoice.dto';

@Injectable()
export class InvoiceService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly buyerService: BuyerService,
        private readonly supplierService: SupplierService,
        private readonly productService: ProductService,
        private readonly serviceService: ServiceService,
        private readonly tapPaymentService: TapPaymentsService,
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
                                  }) as InvoiceItemDto,
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
                buyer: await this.buyerService.toBuyerResponseDto(
                    entity.buyer.user,
                    entity.buyer,
                ),
                supplier: await this.supplierService.toSupplierResponseDTO(
                    entity.supplier.user,
                    entity.supplier,
                ),
                product: await this.productService.toProductResponseDto(
                    entity.product,
                ),
                amount: entity.amount,
                createdAt: entity.amout,
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
                            relatedProduct: { include: { category: true } },
                            relatedService: { include: { category: true } },
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
                    product: true,
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
                return { some: { relatedProductId: { not: null } } };
            case 'services':
                return { some: { relatedServiceId: { not: null } } };
            // case 'groups':
            //     return { some: { relatedGroupId: { not: null } } }; // if exists
            // case 'bids':
            //     return { some: { relatedBidId: { not: null } } }; // if exists
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
                        relatedProduct: { include: { category: true } },
                        relatedService: { include: { category: true } },
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
                product: true,
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
            uponDeliveryAmount = 0;
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
                        relatedProduct: { include: { category: true } },
                        relatedService: { include: { category: true } },
                    },
                },
            },
        });

        // Convert to InvoiceResponseDto
        return await this.toInvoiceResponseDto(invoice, 'INVOICE');
    }

    async createPreInvoice() {}

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
                        relatedProduct: { include: { category: true } },
                        relatedService: { include: { category: true } },
                    },
                },
            },
        });

        return (await this.toInvoiceResponseDto(
            updatedInvoice,
            'INVOICE',
        )) as InvoiceResponseDto;
    }

    async payInvoice(userId: string, id: string) {
        // --- 1. Verify invoice exists and belongs to the buyer ---
        const invoice = await this.prisma.invoice.findUnique({
            where: { id },
            include: {
                buyer: { include: { user: true, card: true } },
                invoiceItems: { include: { product: true } },
            },
        });

        if (!invoice) throw new NotFoundException('Invoice not found');
        if (invoice.buyer.userId !== userId)
            throw new ForbiddenException(
                'You are not allowed to pay this invoice',
            );
        if (invoice.isPaid)
            throw new BadRequestException('Invoice already paid');

        if (!['ACCEPTED', 'PARTIALLY_PAID'].includes(invoice.status))
            throw new BadRequestException(
                'Invoice must be accepted or partially paid to proceed with payment',
            );

        const buyer = invoice.buyer;

        // --- 2. Validate buyer payment info ---
        if (!buyer.card)
            throw new BadRequestException('No saved card found for this buyer');
        if (!buyer.user.tapCustomerId)
            throw new BadRequestException('Missing Tap customer ID');

        // --- 3. Calculate totals (like checkoutCart) ---
        const itemsTotal = invoice.invoiceItems.reduce(
            (sum, item) => sum + item.quantity * item.product.price,
            0,
        );

        const deliveryFees =
            invoice.deliveryFees ??
            invoice.invoiceItems.reduce(
                (sum, item) =>
                    sum + (item.product?.supplier?.deliveryFees ?? 0),
                0,
            );

        const totalAmount = itemsTotal + deliveryFees;

        // --- 4. Create Tap charge ---
        const token = await this.tapPaymentsService.createTokenFromSavedCard(
            buyer.user.tapCustomerId,
            buyer.card.tapCardId,
        );

        const charge = await this.tapPaymentsService.payWithSavedCard(
            buyer.user.tapCustomerId,
            token.id,
            buyer.card.tapCardId,
            totalAmount,
            'http://localhost:5137/payment/invoice/callback', // TODO: replace with real callback URL
        );

        // --- 5. Redirect for 3DS if needed ---
        if (charge.status === 'INITIATED' && charge.transaction?.url) {
            return {
                message: 'Redirect for authentication',
                redirectUrl: charge.transaction.url,
                chargeId: charge.id,
            };
        }

        // --- 6. Confirm successful charge ---
        if (!['CAPTURED', 'AUTHORIZED'].includes(charge.status)) {
            throw new BadRequestException(
                `Payment failed. Charge status: ${charge.status}`,
            );
        }

        // --- 7. Mark invoice as paid & reduce stock ---
        await this.prisma.$transaction(async (tx) => {
            // reduce product stock
            for (const item of invoice.invoiceItems) {
                await tx.product.update({
                    where: { id: item.product.id },
                    data: { stock: item.product.stock - item.quantity },
                });
            }

            // mark invoice as paid
            await tx.invoice.update({
                where: { id: invoice.id },
                data: {
                    isPaid: true,
                    status: 'PAID',
                    tapChargeId: charge.id,
                    totalPaid: totalAmount,
                    paidAt: new Date(),
                },
            });
        });

        // --- 8. Return summary ---
        return {
            message: 'Invoice paid successfully',
            tapChargeId: charge.id,
            buyerId: buyer.id,
            invoiceId: invoice.id,
            totalPaid: totalAmount,
        };
    }
}
