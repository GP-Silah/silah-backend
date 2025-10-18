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
import { GroupPurchaseDeadline, GroupPurchaseStatus } from '@prisma/client';

@Injectable()
export class GroupPurchaseService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly productService: ProductService,
        private readonly supplierService: SupplierService,
        private readonly buyerService: BuyerService,
    ) {}

    async toGroupPurchaseResponseDto(
        groupPurchase: any,
    ): Promise<GroupPurchaseResponseDto> {
        // Make sure related entities are loaded
        if (
            !groupPurchase.product ||
            !groupPurchase.supplier ||
            !groupPurchase.buyers
        ) {
            groupPurchase = await this.prisma.groupPurchase.findUnique({
                where: { id: groupPurchase.id },
                include: {
                    product: { include: { category: true } },
                    supplier: { include: { user: true } },
                    joinedBuyers: {
                        include: {
                            buyer: { include: { user: true } },
                        },
                    },
                },
            });
        }

        const product = groupPurchase.product;
        const supplier = groupPurchase.supplier;

        // Compute derived fields
        const remainingQuantity = Math.max(
            0,
            groupPurchase.minGroupQuantity - groupPurchase.actualGroupQuantity,
        );

        const discountPercentage = product.price
            ? Math.round(
                  ((product.price - groupPurchase.groupUnitPrice) /
                      product.price) *
                      100,
              )
            : 0;

        // Base fields
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

        // Relations
        dto.product = await this.productService.toProductResponseDto(product);
        dto.supplier = await this.supplierService.toSupplierResponseDTO(
            supplier.user,
            supplier,
        );

        // Joined buyers
        dto.joinedBuyers = await Promise.all(
            groupPurchase.buyers.map(async (buyerRelation) => {
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
            }),
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
        const group = this.prisma.groupPurchase.findUnique({
            where: { id: groupId },
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
        const now = new Date();
        const groupPurchases = await this.prisma.groupPurchase.findMany({
            where: {
                productId,
                city,
                status: GroupPurchaseStatus.OPEN,
                deadline: { gt: now }, // still valid
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

        // Compute dynamic filter: actual < minGroup
        // Prisma can’t compare two columns directly, so we filter manually
        // Note: no need for this filter really..
        const suitableGroups = groupPurchases.filter(
            (gp) => gp.actualGroupQuantity < gp.minGroupQuantity,
        );

        // Map to DTOs
        const dtoList = await Promise.all(
            suitableGroups.map((gp) => this.toGroupPurchaseResponseDto(gp)),
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
        const totalPrice = quantity * groupUnitPrice;

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
                        priceBasedQuantity: totalPrice,
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

        //TODO: 6. Create preinvoice

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
        const newTotalPrice = group.totalPrice + addedPrice;

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

        // 7. If group successeded create invoices for every joiend buyer

        // 8. Return DTO
        return this.toGroupPurchaseResponseDto(updatedGroup);
    }
}
