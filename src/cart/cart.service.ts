import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { CartResponseDto } from './dtos/cartResponse.dto';
import { AddCartItemDto } from './dtos/addCartItem.dto';

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
        // 1️⃣ Find the buyer
        const buyer = await this.prisma.buyer.findUnique({
            where: { userId },
        });
        if (!buyer) throw new NotFoundException('Buyer not found');

        // 2️⃣ Find or create active cart
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

        // 3️⃣ Find or create CartBySupplier (grouped by supplier)
        let cartBySupplier = await this.prisma.cartBySupplier.findFirst({
            where: { cartId: activeCart.id, supplierId: dto.supplierId },
        });

        if (!cartBySupplier) {
            cartBySupplier = await this.prisma.cartBySupplier.create({
                data: {
                    cartId: activeCart.id,
                    supplierId: dto.supplierId,
                    deliveryFee: 0, // optionally fetch from supplier
                    subTotal: 0,
                    supplierTotalPrice: 0,
                },
            });
        }

        // 4️⃣ Check if product already exists in this supplier's cart
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

        // 5️⃣ Update supplier subtotal and total
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

        // 6️⃣ Update cart totals
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

        // 7️⃣ Fetch updated cart with all relations for DTO
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
}
