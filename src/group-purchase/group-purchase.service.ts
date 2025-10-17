import { Injectable, NotFoundException } from '@nestjs/common';
import { BuyerService } from 'src/buyer/buyer.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { ProductService } from 'src/product/product.service';
import { SupplierService } from 'src/supplier/supplier.service';
import {
    GroupPurchaseBuyerResponseDto,
    GroupPurchaseResponseDto,
} from './dtos/groupPurchaseResponse.dto';
import { GroupPurchaseStatus } from '@prisma/client';

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

    async startGroupPurchase(
        userId: string,
        productId: string,
        quantity: number,
    ) {}

    async joinGroupPurchase(
        userId: string,
        groupId: string,
        quantity: number,
    ) {}
}
