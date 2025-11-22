import {
    BadRequestException,
    ConflictException,
    Injectable,
    NotFoundException,
} from '@nestjs/common';
import { BuyerService } from 'src/buyer/buyer.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { ProductService } from 'src/product/product.service';
import { SupplierService } from 'src/supplier/supplier.service';
import {
    GroupPurchaseBuyerResponseDto,
    GroupPurchaseResponseDto,
} from './dtos/groupPurchaseResponse.dto';
import {
    GroupPurchaseDeadline,
    GroupPurchaseStatus,
    InvoiceStatus,
    InvoiceTermsOfPayment,
    NotificationEntityType,
    NotificationType,
    PreInvoiceStatus,
} from '@prisma/client';
import { addDays } from 'date-fns';
import { NotificationService } from 'src/notification/notification.service';

@Injectable()
export class GroupPurchaseService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly productService: ProductService,
        private readonly supplierService: SupplierService,
        private readonly buyerService: BuyerService,
        private readonly notificationService: NotificationService,
    ) {}

    // --- 1. Map GroupPurchaseBuyer to DTO ---
    async toGroupPurchaseBuyerResponseDto(
        buyerRelation: any,
    ): Promise<GroupPurchaseBuyerResponseDto> {
        const buyerDto = new GroupPurchaseBuyerResponseDto();
        buyerDto.groupPurchaseBuyerId = buyerRelation.id;
        buyerDto.quantity = buyerRelation.quantity;
        buyerDto.priceBasedQuantity = buyerRelation.priceBasedQuantity;
        buyerDto.joinedAt = buyerRelation.joinedAt;
        buyerDto.buyer = await this.buyerService.toBuyerResponseDto(
            buyerRelation.buyer.user,
            buyerRelation.buyer,
        );
        return buyerDto;
    }

    // --- 2. Map GroupPurchase to DTO ---
    async toGroupPurchaseResponseDto(
        groupPurchase: any,
    ): Promise<GroupPurchaseResponseDto> {
        const product = groupPurchase.product;
        const supplier = groupPurchase.supplier;

        const remainingQuantity = Math.max(
            0,
            groupPurchase.minGroupQuantity - groupPurchase.actualGroupQuantity,
        );

        const discountPercentage = product.price
            ? Math.round(
                  ((product.price - product.groupPurchasePrice) /
                      product.price) *
                      100,
              )
            : 0;

        const dto = new GroupPurchaseResponseDto();
        dto.groupPurchaseId = groupPurchase.id;
        dto.city = groupPurchase.city;
        dto.minGroupQuantity = groupPurchase.minGroupQuantity;
        dto.actualGroupQuantity = groupPurchase.actualGroupQuantity;
        dto.remainingQuantity = remainingQuantity;
        dto.totalPrice = groupPurchase.totalPrice;
        dto.groupUnitPrice = groupPurchase.groupUnitPrice;
        dto.discountPercentage = discountPercentage;
        dto.deadline = groupPurchase.deadline;
        dto.status = groupPurchase.status;
        dto.createdAt = groupPurchase.createdAt;

        dto.product = await this.productService.toProductResponseDto(product);
        dto.supplier = await this.supplierService.toSupplierResponseDTO(
            supplier.user,
            supplier,
        );

        dto.joinedBuyers = await Promise.all(
            groupPurchase.joinedBuyers.map((buyerRelation) =>
                this.toGroupPurchaseBuyerResponseDto(buyerRelation),
            ),
        );

        return dto;
    }

    async getAllGroupPurchaseForProduct(productId: string) {
        // Validate product existence
        const product = await this.prisma.product.findFirst({
            where: { id: productId, isDeleted: false },
        });
        if (!product) {
            throw new NotFoundException(
                `Product with ID ${productId} not found`,
            );
        }

        // Fetch all group purchases for this product
        const groupPurchases = await this.prisma.groupPurchase.findMany({
            where: { productId },
            include: {
                product: { include: { category: true } },
                supplier: { include: { user: true } },
                joinedBuyers: {
                    include: { buyer: { include: { user: true } } },
                },
            },
            orderBy: { createdAt: 'desc' },
        });

        // Map to DTOs
        const dtoList = await Promise.all(
            groupPurchases.map((gp) => this.toGroupPurchaseResponseDto(gp)),
        );

        return dtoList;
    }

    async getGroupById(groupId: string) {
        const group = await this.prisma.groupPurchase.findUnique({
            where: { id: groupId },
            include: {
                product: { include: { category: true } },
                supplier: { include: { user: true } },
                joinedBuyers: {
                    include: { buyer: { include: { user: true } } },
                },
            },
        });
        if (!group) {
            throw new NotFoundException(
                `Group Purchase with ID ${groupId} not found`,
            );
        }
        return this.toGroupPurchaseResponseDto(group);
    }

    async getSuitableGroupPurchasesForProduct(
        userId: string,
        productId: string,
    ): Promise<GroupPurchaseResponseDto[]> {
        // Validate product
        const product = await this.prisma.product.findFirst({
            where: { id: productId, isDeleted: false },
        });
        if (!product) {
            throw new NotFoundException(
                `Product with ID ${productId} not found`,
            );
        }

        // Get buyer & city
        const buyer = await this.prisma.buyer.findUnique({
            where: { userId },
            include: { user: true },
        });
        if (!buyer) {
            throw new NotFoundException(`Buyer not found`);
        }
        const city = buyer.user.city.toLowerCase();

        // Find open & suitable group purchases
        const groupPurchases = await this.prisma.groupPurchase.findMany({
            where: {
                productId,
                city,
                status: GroupPurchaseStatus.OPEN,
            },
            include: {
                product: { include: { category: true } },
                supplier: { include: { user: true } },
                joinedBuyers: {
                    include: { buyer: { include: { user: true } } },
                },
            },
            orderBy: [{ deadline: 'asc' }, { createdAt: 'desc' }],
        });

        // Map to DTOs
        const dtoList = await Promise.all(
            groupPurchases.map((gp) => this.toGroupPurchaseResponseDto(gp)),
        );

        return dtoList;
    }

    // --- map enum to number of days ---
    private deadlineDaysFromEnum(
        enumValue?: GroupPurchaseDeadline | null,
    ): number {
        // map string enum values to days
        const map: Record<string, number> = {
            THREE_DAYS: 3,
            FIVE_DAYS: 5,
            SEVEN_DAYS: 7,
        };

        if (!enumValue) return 3; // fallback default
        return map[enumValue] ?? 3;
    }

    async startGroupPurchase(userId, productId, quantity) {
        // 1. Validate buyer exists
        const buyer = await this.prisma.buyer.findUnique({
            where: { userId },
            include: { user: true },
        });
        if (!buyer) throw new NotFoundException('Buyer not found');
        const city = buyer.user.city.toLowerCase();

        // 2. Validate product exists and published
        const product = await this.prisma.product.findFirst({
            where: {
                id: productId,
                isDeleted: false,
                isPublished: true,
                supplier: { isStoreClosed: false },
            },
            include: { supplier: { include: { user: true } } },
        });
        if (!product) throw new NotFoundException('Product not found');
        if (!product.allowGroupPurchase) {
            throw new BadRequestException(
                'Group purchases are not enabled for this product',
            );
        }

        // 3. Check if an open group purchase already exists
        const existingOpenGroup = await this.prisma.groupPurchase.findFirst({
            where: { productId, status: 'OPEN', city },
        });
        if (existingOpenGroup)
            throw new ConflictException(
                'There is already an open group purchase for this product',
            );

        // 4. Compute initial values
        const groupUnitPrice = product.groupPurchasePrice!;
        const priceBasedQuantity = quantity * groupUnitPrice;
        const totalPrice = priceBasedQuantity + product.supplier!.deliveryFees;

        const days = this.deadlineDaysFromEnum(product.groupPurchaseDuration!);
        const deadline = new Date();
        deadline.setDate(deadline.getDate() + days);

        // 5. Create group purchase
        const groupPurchase = await this.prisma.groupPurchase.create({
            data: {
                productId,
                supplierId: product.supplierId!,
                city,
                minGroupQuantity: product.minGroupOrderQuantity!,
                actualGroupQuantity: quantity,
                totalPrice,
                deadline,
                status: GroupPurchaseStatus.OPEN,
                joinedBuyers: {
                    create: {
                        buyerId: buyer.id,
                        quantity,
                        priceBasedQuantity,
                        totalPrice,
                        joinedAt: new Date(),
                    },
                },
            },
            include: {
                product: { include: { category: true } },
                supplier: { include: { user: true } },
                joinedBuyers: {
                    include: { buyer: { include: { user: true } } },
                },
            },
        });

        // 6. Create preinvoice
        const preInvoice = await this.prisma.preInvoice.create({
            data: {
                groupPurchaseBuyerId: groupPurchase.joinedBuyers[0].id,
                buyerId: buyer.id,
                supplierId: groupPurchase.supplierId,
                productId: product.id,
                amount: totalPrice,
                status: PreInvoiceStatus.PENDING,
            },
        });

        // 7. Return response DTO
        return this.toGroupPurchaseResponseDto(groupPurchase);
    }

    async joinGroupPurchase(userId: string, groupId: string, quantity: number) {
        // 1. Validate buyer
        const buyer = await this.prisma.buyer.findUnique({
            where: { userId },
            include: { user: true },
        });
        if (!buyer) throw new NotFoundException('Buyer not found');
        const city = buyer.user.city.toLowerCase();

        // 2. Validate group
        const group = await this.prisma.groupPurchase.findUnique({
            where: { id: groupId },
            include: {
                product: true,
                supplier: { include: { user: true } },
                joinedBuyers: { include: { buyer: true } },
            },
        });
        if (!group) throw new NotFoundException('Group purchase not found');

        if (group.status !== GroupPurchaseStatus.OPEN)
            throw new BadRequestException('This group purchase is not open');

        if (group.deadline < new Date())
            throw new BadRequestException('This group purchase has expired');

        if (group.city.toLowerCase() !== city)
            throw new BadRequestException(
                'You can only join group purchases in your city',
            );

        // 3. Check if already joined
        const alreadyJoined = await this.prisma.groupPurchaseBuyer.findFirst({
            where: { buyerId: buyer.id, groupPurchaseId: groupId },
        });
        if (alreadyJoined)
            throw new ConflictException(
                'You already joined this group purchase',
            );

        // 4. Compute new totals
        const product = group.product;
        const newActual = group.actualGroupQuantity + quantity;
        const groupUnitPrice = product.groupPurchasePrice!;
        const addedPrice = quantity * groupUnitPrice;
        const totalPrice = addedPrice + group.supplier.deliveryFees;
        const newPriceBasedQuantity = group.totalPrice + addedPrice;
        const newTotalPrice = group.totalPrice + totalPrice;

        // if (newActual > group.minGroupQuantity * 5) {
        //     // just to prevent weird data errors or overbuying
        //     throw new BadRequestException('Group purchase limit exceeded');
        // }

        // Compute number of buyers (existing + new one)
        const currentBuyerCount = group.joinedBuyers.length;
        const newBuyerCount = currentBuyerCount + 1;

        // Determine new status
        let newStatus: GroupPurchaseStatus = group.status;
        if (
            newActual >= group.minGroupQuantity && // quantity goal met
            newBuyerCount >= 5 // at least 5 buyers joined
        ) {
            newStatus = GroupPurchaseStatus.CLOSED;
        } else {
            newStatus = GroupPurchaseStatus.OPEN;
        }

        // 5. Add buyer and update totals
        const updatedGroup = await this.prisma.groupPurchase.update({
            where: { id: groupId },
            data: {
                actualGroupQuantity: newActual,
                totalPrice: newTotalPrice,
                joinedBuyers: {
                    create: {
                        buyerId: buyer.id,
                        quantity,
                        priceBasedQuantity: addedPrice,
                        totalPrice,
                        joinedAt: new Date(),
                    },
                },
                status: newStatus,
            },
            include: {
                product: { include: { category: true } },
                supplier: { include: { user: true } },
                joinedBuyers: {
                    include: { buyer: { include: { user: true } } },
                },
            },
        });

        // 6. Create preinvocie for the new joined buyer
        const newJoinedBuyer = await this.prisma.groupPurchaseBuyer.findFirst({
            where: {
                buyerId: buyer.id,
                groupPurchaseId: groupId,
            },
            include: { buyer: { include: { user: true } } },
        });

        const preInvoice = await this.prisma.preInvoice.create({
            data: {
                groupPurchaseBuyerId: newJoinedBuyer!.id,
                buyerId: buyer.id,
                supplierId: updatedGroup.supplierId,
                productId: product.id,
                amount: totalPrice,
                status: PreInvoiceStatus.PENDING,
            },
        });

        // 7. If group succeeded, create invoices for every joined buyer
        if (updatedGroup.status === GroupPurchaseStatus.CLOSED) {
            // Fetch all pre-invoices for this group
            const preInvoices = await this.prisma.preInvoice.findMany({
                where: {
                    groupPurchaseBuyer: { groupPurchaseId: groupId },
                },
                include: {
                    buyer: true,
                    supplier: true,
                    groupPurchaseBuyer: true,
                },
            });

            for (const pre of preInvoices) {
                // Create invoice
                const invoice = await this.prisma.invoice.create({
                    data: {
                        buyerId: pre.buyerId!,
                        supplierId: pre.supplierId!,
                        deliveryDate: addDays(new Date(), 30),
                        termsOfPayment: InvoiceTermsOfPayment.FULL,
                        uponDeliveryAmount: pre.amount,
                        amount: pre.amount,
                        notesAndTerms: `System Note: This invoice was automatically generated because the group purchase for "${updatedGroup.product.name}" has successfully met all requirements. The expected delivery date has been set to 30 days from the invoice creation by system default.`,
                        status: InvoiceStatus.PENDING,
                    },
                });

                // Link pre-invoice to this invoice and mark success
                await this.prisma.preInvoice.update({
                    where: { id: pre.id },
                    data: {
                        invoiceId: invoice.id,
                        status: PreInvoiceStatus.SUCCESSFUL,
                    },
                });

                await this.notificationService.createNotification({
                    senderUserId: pre.supplier!.userId,
                    receiverUserId: pre.buyer!.userId,
                    type: NotificationType.GROUP_PURCHASE_STATUS_CHANGED,
                    title: 'Group Purchase Status Changed!',
                    content: `The group purchase "${group.id}" has closed successfully. Your pre-invoice has been upgraded to a full invoice. You can procced with payment now.`,
                    entityId: group.id,
                    entityType: NotificationEntityType.GROUP_PURCHASE,
                });
            }
        }

        // 8. Return DTO
        return this.toGroupPurchaseResponseDto(updatedGroup);
    }
}
