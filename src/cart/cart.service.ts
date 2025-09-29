import {
    BadRequestException,
    Injectable,
    NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { CartResponseDto } from './dtos/cartResponse.dto';
import { AddCartItemDto } from './dtos/addCartItem.dto';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class CartService {
    constructor(private readonly prisma: PrismaService) {}

    private toCartResponseDto(cart: any): CartResponseDto {
        return {
            id: cart.id,
            buyerId: cart.buyerId,
            productsTotal: cart.productsTotal,
            deliveryFees: cart.deliveryFees,
            cartTotal: cart.cartTotal,
            isBought: cart.isBought,
            suppliers: cart.suppliers.map((s: any) => ({
                id: s.id,
                supplierId: s.supplierId,
                deliveryFee: s.deliveryFee,
                subTotal: s.subTotal,
                supplierTotalPrice: s.supplierTotalPrice,
                cartItems: s.cartItems.map((item: any) => ({
                    id: item.id,
                    productId: item.productId,
                    productName: item.product.name,
                    productPrice: item.product.price,
                    quantity: item.quantity,
                    itemTotalPrice: item.itemTotalPrice,
                })),
            })),
        };
    }

    async getBuyerActiveCart(
        userId: string,
        targetLang?: 'ar' | 'en',
    ): Promise<CartResponseDto> {
        const buyer = await this.prisma.buyer.findUnique({
            where: { userId },
        });
        if (!buyer) throw new NotFoundException('Buyer not found');
        const activeCart = await this.prisma.cart.findFirst({
            where: { buyerId: buyer.id, isBought: false, isDeleted: false },
            include: {
                suppliers: {
                    include: {
                        cartItems: {
                            include: {
                                product: true, // we want product info
                            },
                        },
                        supplier: true, // we want supplier info
                    },
                },
            },
        });
        if (!activeCart)
            throw new NotFoundException('No active cart for this buyer');
        return this.toCartResponseDto(activeCart);
    }

    async addItem(userId: string, dto: AddCartItemDto) {
        // Find the supplier
        const supplier = await this.prisma.supplier.findUnique({
            where: { id: dto.supplierId, isDeleted: false },
        });
        if (!supplier) {
            throw new BadRequestException(
                `Supplier with id ${dto.supplierId} is not found`,
            );
        }

        // Find the buyer
        const buyer = await this.prisma.buyer.findUnique({
            where: { userId },
        });
        if (!buyer) throw new NotFoundException('Buyer not found');

        // Find or create active cart
        let activeCart = await this.prisma.cart.findFirst({
            where: { buyerId: buyer.id, isBought: false, isDeleted: false },
        });

        if (!activeCart) {
            // Create a new cart if none exists
            activeCart = await this.prisma.cart.create({
                data: {
                    buyerId: buyer.id,
                    productsTotal: 0,
                    deliveryFees: 0,
                    cartTotal: 0,
                },
            });
        }

        // Find or create CartBySupplier (grouped by supplier)
        let cartBySupplier = await this.prisma.cartBySupplier.findFirst({
            where: { cartId: activeCart.id, supplierId: supplier.id },
        });

        if (!cartBySupplier) {
            cartBySupplier = await this.prisma.cartBySupplier.create({
                data: {
                    cartId: activeCart.id,
                    supplierId: supplier.id,
                    deliveryFee: supplier.deliveryFees,
                    subTotal: 0,
                    supplierTotalPrice: 0,
                },
            });
        }

        // Check if product already exists in this supplier's cart
        let cartItem = await this.prisma.cartItem.findFirst({
            where: {
                cartBySupplierId: cartBySupplier.id,
                productId: dto.productId,
            },
        });

        const product = await this.prisma.product.findUnique({
            where: { id: dto.productId },
        });
        if (!product) throw new NotFoundException('Product not found');

        if (cartItem) {
            // Update quantity and total price
            cartItem = await this.prisma.cartItem.update({
                where: { id: cartItem.id },
                data: {
                    quantity: cartItem.quantity + dto.quantity,
                    itemTotalPrice:
                        (cartItem.quantity + dto.quantity) * product.price,
                },
            });
        } else {
            // Create new cart item
            cartItem = await this.prisma.cartItem.create({
                data: {
                    cartBySupplierId: cartBySupplier.id,
                    productId: dto.productId,
                    quantity: dto.quantity,
                    itemTotalPrice: dto.quantity * product.price,
                },
            });
        }

        // Update supplier subtotal and total
        const cartItemsForSupplier = await this.prisma.cartItem.findMany({
            where: { cartBySupplierId: cartBySupplier.id },
        });
        const subTotal = cartItemsForSupplier.reduce(
            (sum, item) => sum + item.itemTotalPrice,
            0,
        );
        await this.prisma.cartBySupplier.update({
            where: { id: cartBySupplier.id },
            data: {
                subTotal,
                supplierTotalPrice: subTotal + cartBySupplier.deliveryFee,
            },
        });

        // Update cart totals
        const cartSuppliers = await this.prisma.cartBySupplier.findMany({
            where: { cartId: activeCart.id },
        });
        const productsTotal = cartSuppliers.reduce(
            (sum, s) => sum + s.subTotal,
            0,
        );
        const deliveryFees = cartSuppliers.reduce(
            (sum, s) => sum + s.deliveryFee,
            0,
        );
        const cartTotal = productsTotal + deliveryFees;

        await this.prisma.cart.update({
            where: { id: activeCart.id },
            data: { productsTotal, deliveryFees, cartTotal },
        });

        // Fetch updated cart with all relations for DTO
        const newCart = await this.prisma.cart.findFirst({
            where: { id: activeCart.id },
            include: {
                suppliers: {
                    include: {
                        cartItems: {
                            include: { product: true },
                        },
                        supplier: true,
                    },
                },
            },
        });

        return this.toCartResponseDto(newCart!);
    }

    async updateItemQuantity(
        userId: string,
        cartId: string,
        itemId: number,
        newQuantity: number,
    ): Promise<CartResponseDto> {
        if (newQuantity < 1) {
            throw new BadRequestException('Quantity must be at least 1');
        }

        // Ensure cart belongs to buyer
        const buyer = await this.prisma.buyer.findUnique({ where: { userId } });
        if (!buyer) throw new NotFoundException('Buyer not found');

        const cart = await this.prisma.cart.findFirst({
            where: {
                id: cartId,
                buyerId: buyer.id,
                isBought: false,
                isDeleted: false,
            },
            include: {
                suppliers: {
                    include: {
                        cartItems: { include: { product: true } },
                        supplier: true,
                    },
                },
            },
        });
        if (!cart) throw new NotFoundException('Cart not found');

        // Update cart item
        const item = await this.prisma.cartItem.findUnique({
            where: { id: itemId },
            include: { product: true, cartBySupplier: true },
        });
        if (!item || item.cartBySupplier.cartId !== cart.id) {
            throw new NotFoundException('Item not found in this cart');
        }

        const updatedItem = await this.prisma.cartItem.update({
            where: { id: itemId },
            data: {
                quantity: newQuantity,
                itemTotalPrice: newQuantity * item.product.price,
            },
        });

        // Recalculate totals
        await this.recalculateCartTotals(cart.id);

        // Return updated cart
        const newCart = await this.findCartWithRelations(cart.id);
        return this.toCartResponseDto(newCart!);
    }

    async removeItem(
        userId: string,
        cartId: string,
        itemId: number,
    ): Promise<CartResponseDto> {
        const buyer = await this.prisma.buyer.findUnique({ where: { userId } });
        if (!buyer) throw new NotFoundException('Buyer not found');

        const cartItem = await this.prisma.cartItem.findUnique({
            where: { id: itemId },
            include: { cartBySupplier: true },
        });
        if (!cartItem || cartItem.cartBySupplier.cartId !== cartId) {
            throw new NotFoundException('Item not found in this cart');
        }

        await this.prisma.cartItem.delete({ where: { id: itemId } });

        // If supplier has no more items, remove the supplier group
        const remaining = await this.prisma.cartItem.count({
            where: { cartBySupplierId: cartItem.cartBySupplierId },
        });
        if (remaining === 0) {
            await this.prisma.cartBySupplier.delete({
                where: { id: cartItem.cartBySupplierId },
            });
        }

        await this.recalculateCartTotals(cartId);

        const newCart = await this.findCartWithRelations(cartId);
        return this.toCartResponseDto(newCart!);
    }

    async deleteCart(userId: string, cartId: string): Promise<void> {
        const buyer = await this.prisma.buyer.findUnique({ where: { userId } });
        if (!buyer) throw new NotFoundException('Buyer not found');

        const cart = await this.prisma.cart.findFirst({
            where: { id: cartId, buyerId: buyer.id },
        });
        if (!cart) throw new NotFoundException('Cart not found');

        await this.prisma.cart.update({
            where: { id: cartId },
            data: { isDeleted: true, deletedAt: new Date() },
        });
    }

    async removeSupplierFromCart(
        userId: string,
        cartId: string,
        supplierId: string,
    ): Promise<CartResponseDto> {
        const buyer = await this.prisma.buyer.findUnique({ where: { userId } });
        if (!buyer) throw new NotFoundException('Buyer not found');

        const cartBySupplier = await this.prisma.cartBySupplier.findFirst({
            where: { cartId, supplierId },
        });
        if (!cartBySupplier) {
            throw new NotFoundException('Supplier not found in this cart');
        }

        // Cascade deletes its items due to schema
        await this.prisma.cartBySupplier.delete({
            where: { id: cartBySupplier.id },
        });

        await this.recalculateCartTotals(cartId);

        const newCart = await this.findCartWithRelations(cartId);
        return this.toCartResponseDto(newCart!);
    }

    async checkoutCart(userId: string, cartId: string) {
        // Step 1: find buyer
        const buyer = await this.prisma.buyer.findUnique({ where: { userId } });
        if (!buyer) throw new NotFoundException('Buyer not found');

        // Step 2: get cart (must be active)
        const cart = await this.prisma.cart.findFirst({
            where: {
                id: cartId,
                buyerId: buyer.id,
                isBought: false,
                isDeleted: false,
            },
            include: {
                suppliers: {
                    include: {
                        cartItems: {
                            include: { product: true },
                        },
                        supplier: true,
                    },
                },
            },
        });
        if (!cart) throw new NotFoundException('Active cart not found');
        if (cart.suppliers.length === 0)
            throw new BadRequestException('Cart is empty');

        // Step 3: generate checkoutId (groups orders from same checkout)
        const checkoutId = uuidv4();

        // Step 4: for each supplier in the cart → create order
        const orders = await Promise.all(
            cart.suppliers.map((supplierCart) => {
                const finalPrice = supplierCart.supplierTotalPrice; // subtotal + delivery fee

                return this.prisma.order.create({
                    data: {
                        checkoutId,
                        buyerId: buyer.id,
                        cartId: cart.id,
                        supplierId: supplierCart.supplierId,
                        finalPrice,
                        // status defaults to PENDING
                    },
                });
            }),
        );

        // Step 5: mark cart as bought
        await this.prisma.cart.update({
            where: { id: cart.id },
            data: { isBought: true },
        });

        // Step 6: payment integration (for the whole checkout)
        // TODO: integrate with payment gateway (Tap)

        // Step 7: return orders grouped by checkoutId
        return {
            message: 'Paid successfully',
            checkoutId,
            buyerId: buyer.id,
            cartId: cart.id,
            totalPaid: cart.cartTotal,
            orders,
        };
    }

    private async recalculateCartTotals(cartId: string): Promise<void> {
        const cartSuppliers = await this.prisma.cartBySupplier.findMany({
            where: { cartId },
        });

        const productsTotal = cartSuppliers.reduce(
            (sum, s) => sum + s.subTotal,
            0,
        );
        const deliveryFees = cartSuppliers.reduce(
            (sum, s) => sum + s.deliveryFee,
            0,
        );
        const cartTotal = productsTotal + deliveryFees;

        await this.prisma.cart.update({
            where: { id: cartId },
            data: { productsTotal, deliveryFees, cartTotal },
        });
    }

    private async findCartWithRelations(cartId: string) {
        return this.prisma.cart.findFirst({
            where: { id: cartId },
            include: {
                suppliers: {
                    include: {
                        cartItems: { include: { product: true } },
                        supplier: true,
                    },
                },
            },
        });
    }
}
