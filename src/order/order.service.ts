import {
    BadRequestException,
    Injectable,
    NotFoundException,
} from '@nestjs/common';
import { CartService } from 'src/cart/cart.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { OrderResponseDto } from './dtos/orderResponse.dto';
import {
    CartItemResponseDto,
    CartResponseDto,
} from 'src/cart/dtos/cartResponse.dto';
import { OrderStatus } from '@prisma/client';
import { BuyerService } from 'src/buyer/buyer.service';
import { SupplierService } from 'src/supplier/supplier.service';
import { ProductService } from 'src/product/product.service';

@Injectable()
export class OrderService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly cartService: CartService,
        private readonly buyerService: BuyerService,
        private readonly supplierService: SupplierService,
        private readonly productService: ProductService,
    ) {}

    async toOrderResponseDto(order: any): Promise<OrderResponseDto> {
        // Convert the cart into your standard DTO
        const cartDto: CartResponseDto =
            await this.cartService.toCartResponseDto(order.cart);

        // Get the supplier slice inside the cart
        const supplierInCart = cartDto.suppliers.find(
            (s) => s.supplierId === order.supplierId,
        );

        // Extract cart items belonging to this supplier
        const items: CartItemResponseDto[] = supplierInCart
            ? supplierInCart.cartItems
            : [];

        // Collect products from those items
        const products = await Promise.all(
            items.map(async (i) => {
                const product = await this.prisma.product.findUnique({
                    where: { id: i.productId },
                    include: {
                        supplier: { include: { user: true } },
                        category: true,
                    },
                });
                return this.productService.toProductResponseDto(product!);
            }),
        );

        return {
            id: order.id,
            tapChargeId: order.tapChargeId,
            buyerId: order.buyerId ?? undefined,
            cartId: order.cartId,
            supplierId: order.supplierId,
            finalPrice: order.finalPrice,
            status: order.status,
            createdAt: order.createdAt,
            items,

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

            products,
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
                buyer: true,
                supplier: true,
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
                buyer: { include: { user: true } },
                supplier: { include: { user: true } },
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
        });
        if (!order) throw new NotFoundException('Order not found');

        await this.prisma.order.update({
            where: { id: orderId },
            data: {
                status: newStatus,
            },
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
