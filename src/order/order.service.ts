import {
    BadRequestException,
    Injectable,
    NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import {
    OrderItemResponseDto,
    OrderResponseDto,
} from './dtos/orderResponse.dto';

import {
    NotificationEntityType,
    NotificationType,
    OrderStatus,
} from '@prisma/client';
import { BuyerService } from 'src/buyer/buyer.service';
import { SupplierService } from 'src/supplier/supplier.service';
import { ProductService } from 'src/product/product.service';
import { NotificationService } from 'src/notification/notification.service';

@Injectable()
export class OrderService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly buyerService: BuyerService,
        private readonly supplierService: SupplierService,
        private readonly productService: ProductService,
        private readonly notificationService: NotificationService,
    ) {}

    async toOrderResponseDto(order: any): Promise<OrderResponseDto> {
        return {
            orderId: order.id,
            tapChargeId: order.tapChargeId,
            buyerId: order.buyerId ?? undefined,
            cartId: order.cartId,
            supplierId: order.supplierId,
            finalPrice: order.finalPrice,
            status: order.status,
            createdAt: order.createdAt,

            // --- Map order items ---
            items: await Promise.all(
                order.items.map(async (item) => {
                    // Defensive null check (product may be deleted)
                    const productDto = item.product
                        ? await this.productService.toProductResponseDto(
                              item.product,
                          )
                        : undefined;

                    return {
                        orderItemId: item.id,
                        orderId: item.orderId,
                        product: productDto,
                        quantity: item.quantity,
                        unitPrice: item.unitPrice,
                        totalPrice: item.totalPrice,
                        createdAt: item.createdAt,
                    };
                }),
            ),

            // Properly mapped buyer
            buyer: order.buyer
                ? await this.buyerService.toBuyerResponseDto(
                      order.buyer.user, // pass the related user
                      order.buyer, // pass the buyer entity itself
                  )
                : null,

            // Properly mapped supplier
            supplier: order.supplier
                ? await this.supplierService.toSupplierResponseDTO(
                      order.supplier.user, // user relation
                      order.supplier, // supplier entity
                  )
                : null,
        };
    }

    async getMyOrders(
        userId: string,
        status?: OrderStatus,
    ): Promise<OrderResponseDto[]> {
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
            include: { buyer: true, supplier: true },
        });
        if (!user) throw new NotFoundException('User not found');

        let whereCondition: any = {};

        if (user.role === 'BUYER') {
            if (!user.buyer) throw new NotFoundException('Buyer not found');

            // Fetch orders for this buyer
            whereCondition = { buyerId: user.buyer.id };
        } else if (user.role === 'SUPPLIER') {
            if (!user.supplier)
                throw new NotFoundException('Supplier not found');

            // Fetch orders received by this supplier
            whereCondition = { supplierId: user.supplier.id };
        } else {
            // Other roles are not allowed
            throw new BadRequestException(
                'Orders not found for this user role',
            );
        }

        // Apply status filter only if valid
        if (status) {
            whereCondition.status;
        }

        // Fetch orders including cart and cart items
        const orders = await this.prisma.order.findMany({
            where: whereCondition,
            include: {
                buyer: { include: { user: true, card: true } },
                supplier: { include: { user: true } },
                items: {
                    include: {
                        product: {
                            include: {
                                category: true,
                            },
                        },
                    },
                },
            },
            orderBy: { createdAt: 'desc' },
        });

        // Map orders to DTO
        const orderDtos = await Promise.all(
            orders.map((order) => this.toOrderResponseDto(order)),
        );

        return orderDtos;
    }

    async getOrderById(
        userId: string,
        orderId: string,
    ): Promise<OrderResponseDto> {
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
            include: { buyer: true, supplier: true },
        });
        if (!user) throw new NotFoundException('User not found');

        // Fetch the order including cart and cart items
        const order = await this.prisma.order.findUnique({
            where: { id: orderId },
            include: {
                buyer: { include: { user: true, card: true } },
                supplier: { include: { user: true } },
                items: {
                    include: {
                        product: {
                            include: {
                                category: true,
                            },
                        },
                    },
                },
            },
        });

        if (!order) throw new NotFoundException('Order not found');

        // Check if the user is authorized to view this order
        if (user.role === 'BUYER') {
            if (!user.buyer || order.buyerId !== user.buyer.id) {
                throw new NotFoundException('Order not found for this buyer');
            }
        } else if (user.role === 'SUPPLIER') {
            if (!user.supplier || order.supplierId !== user.supplier.id) {
                throw new NotFoundException(
                    'Order not found for this supplier',
                );
            }
        } else {
            throw new BadRequestException(
                'Orders not found for this user role',
            );
        }

        // Map order to DTO
        return this.toOrderResponseDto(order);
    }

    async updateOrderStatus(
        userId: string,
        orderId: string,
        newStatus: OrderStatus,
    ) {
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
            include: { supplier: true },
        });
        if (!user) throw new NotFoundException('User not found');

        const order = await this.prisma.order.findUnique({
            where: { id: orderId, supplierId: user.supplier!.id },
            include: {
                supplier: { include: { user: true } },
                buyer: { include: { user: true } },
            },
        });
        if (!order) throw new NotFoundException('Order not found');

        await this.prisma.order.update({
            where: { id: orderId },
            data: {
                status: newStatus,
            },
        });

        // Send a notification for the buyer
        await this.notificationService.createNotification({
            senderUserId: order.supplier.userId,
            receiverUserId: order.buyer!.userId,
            type: NotificationType.ORDER_STATUS_CHANGED,
            title: 'Order Status Changed!',
            content: `Your order from ${order.supplier!.user.businessName} is now ${newStatus}`,
            entityId: order.id,
            entityType: NotificationEntityType.ORDER,
        });

        return { message: 'Order status updated successfully', newStatus };
    }

    async confirmDelivery(userId: string, orderId: string) {
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
            include: { buyer: true },
        });
        if (!user) throw new NotFoundException('User not found');

        const order = await this.prisma.order.findUnique({
            where: { id: orderId, buyerId: user.buyer!.id },
        });
        if (!order) throw new NotFoundException('Order not found');

        await this.prisma.order.update({
            where: { id: orderId },
            data: {
                status: OrderStatus.COMPLETED,
            },
        });

        return {
            message: 'Order delivery confirmed successfully',
            newStatus: OrderStatus.COMPLETED,
        };
    }
}
