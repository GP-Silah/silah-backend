import {
    BadRequestException,
    Injectable,
    NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { CartResponseDto } from './dtos/cartResponse.dto';
import { AddCartItemDto } from './dtos/addCartItem.dto';
import { v4 as uuidv4 } from 'uuid';
import { TranslationService } from 'src/translation/translation.service';

@Injectable()
export class CartService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly translationService: TranslationService,
    ) {}

    /** --- UTILITY: Get active cart for a buyer --- */
    private async getActiveCartByUserId(userId: string) {
        const buyer = await this.prisma.buyer.findUnique({
            where: { userId },
        });
        if (!buyer) throw new NotFoundException('Buyer not found');

        const cart = await this.prisma.cart.findFirst({
            where: { buyerId: buyer.id, isBought: false, isDeleted: false },
            include: {
                suppliers: {
                    include: {
                        cartItems: { include: { product: true } },
                        supplier: true,
                    },
                },
            },
        });

        if (!cart)
            throw new NotFoundException('No active cart found for this buyer');

        return { cart, buyer };
    }

    private async toCartResponseDto(cart: any): Promise<CartResponseDto> {
        // let targetLang;
        // const lang = cart.user.preferredLanguage.toLocaleLowerCase();
        // if (lang === 'ar' || lang === 'en') {
        //     targetLang = lang;
        // }

        return {
            cartId: cart.id,
            buyerId: cart.buyerId,
            productsTotal: cart.productsTotal,
            deliveryFees: cart.deliveryFees,
            cartTotal: cart.cartTotal,
            isBought: cart.isBought,
            suppliers: await Promise.all(
                cart.suppliers.map(async (s: any) => ({
                    cartBySupplierId: s.id,
                    supplierId: s.supplierId,
                    deliveryFee: s.deliveryFee,
                    subTotal: s.subTotal,
                    supplierTotalPrice: s.supplierTotalPrice,
                    cartItems: await Promise.all(
                        s.cartItems.map(async (item: any) => ({
                            itemId: item.id,
                            productId: item.productId,
                            // productName:
                            //     targetLang === 'en'
                            //         ? item.product.name
                            //         : await this.translationService.translateText(
                            //               item.product.name,
                            //               targetLang,
                            //           ),
                            productPrice: item.product.price,
                            quantity: item.quantity,
                            itemTotalPrice: item.itemTotalPrice,
                        })),
                    ),
                })),
            ),
        };
    }

    async getBuyerActiveCart(userId: string): Promise<CartResponseDto> {
        const { cart } = await this.getActiveCartByUserId(userId);
        return this.toCartResponseDto(cart);
    }

    async addItem(userId: string, dto: AddCartItemDto) {
        // Get the buyer first
        const buyer = await this.prisma.buyer.findUnique({
            where: { userId },
        });
        if (!buyer) throw new NotFoundException('Buyer not found');

        // Try to find an active cart, create one if none exists
        let activeCart = await this.prisma.cart.findFirst({
            where: { buyerId: buyer.id, isBought: false, isDeleted: false },
        });

        if (!activeCart) {
            activeCart = await this.prisma.cart.create({
                data: {
                    buyerId: buyer.id,
                    productsTotal: 0,
                    deliveryFees: 0,
                    cartTotal: 0,
                },
            });
        }

        // Check supplier
        const supplier = await this.prisma.supplier.findUnique({
            where: { id: dto.supplierId, isDeleted: false },
        });
        if (!supplier) throw new BadRequestException('Supplier not found');

        // CartBySupplier
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

        // Product
        const product = await this.prisma.product.findUnique({
            where: { id: dto.productId },
        });
        if (!product) throw new NotFoundException('Product not found');

        // CartItem
        let cartItem = await this.prisma.cartItem.findFirst({
            where: {
                cartBySupplierId: cartBySupplier.id,
                productId: dto.productId,
            },
        });

        if (cartItem) {
            cartItem = await this.prisma.cartItem.update({
                where: { id: cartItem.id },
                data: {
                    quantity: cartItem.quantity + dto.quantity,
                    itemTotalPrice:
                        (cartItem.quantity + dto.quantity) * product.price,
                },
            });
        } else {
            cartItem = await this.prisma.cartItem.create({
                data: {
                    cartBySupplierId: cartBySupplier.id,
                    productId: dto.productId,
                    quantity: dto.quantity,
                    itemTotalPrice: dto.quantity * product.price,
                },
            });
        }

        await this.recalculateCartTotals(activeCart.id);
        const newCart = await this.getCartWithRelations(activeCart.id);
        return this.toCartResponseDto(newCart);
    }

    async updateItemQuantity(
        userId: string,
        itemId: number,
        newQuantity: number,
    ) {
        if (newQuantity < 1)
            throw new BadRequestException('Quantity must be at least 1');

        const { cart } = await this.getActiveCartByUserId(userId);

        const item = await this.prisma.cartItem.findUnique({
            where: { id: itemId },
            include: { cartBySupplier: true, product: true },
        });

        if (!item || item.cartBySupplier.cartId !== cart.id) {
            throw new NotFoundException('Item not found in this cart');
        }

        await this.prisma.cartItem.update({
            where: { id: itemId },
            data: {
                quantity: newQuantity,
                itemTotalPrice: newQuantity * item.product.price,
            },
        });

        await this.recalculateCartTotals(cart.id);
        const updatedCart = await this.getCartWithRelations(cart.id);
        return this.toCartResponseDto(updatedCart);
    }

    async removeItem(userId: string, itemId: number) {
        const { cart } = await this.getActiveCartByUserId(userId);

        const cartItem = await this.prisma.cartItem.findUnique({
            where: { id: itemId },
            include: { cartBySupplier: true },
        });
        if (!cartItem || cartItem.cartBySupplier.cartId !== cart.id) {
            throw new NotFoundException('Item not found in this cart');
        }

        await this.prisma.cartItem.delete({ where: { id: itemId } });

        // If no items left for supplier, remove CartBySupplier
        const remaining = await this.prisma.cartItem.count({
            where: { cartBySupplierId: cartItem.cartBySupplierId },
        });
        if (remaining === 0) {
            await this.prisma.cartBySupplier.delete({
                where: { id: cartItem.cartBySupplierId },
            });
        }

        await this.recalculateCartTotals(cart.id);
        const newCart = await this.getCartWithRelations(cart.id);
        return this.toCartResponseDto(newCart);
    }

    async deleteCart(userId: string): Promise<void> {
        const { cart } = await this.getActiveCartByUserId(userId);
        await this.prisma.cart.update({
            where: { id: cart.id },
            data: { isDeleted: true, deletedAt: new Date() },
        });
    }

    async removeSupplierFromCart(userId: string, supplierId: string) {
        const { cart } = await this.getActiveCartByUserId(userId);

        const cartBySupplier = await this.prisma.cartBySupplier.findFirst({
            where: { cartId: cart.id, supplierId },
        });
        if (!cartBySupplier)
            throw new NotFoundException('Supplier not found in this cart');

        await this.prisma.cartBySupplier.delete({
            where: { id: cartBySupplier.id },
        });

        // If no suppliers left, delete cart
        const remainingSuppliers = await this.prisma.cartBySupplier.count({
            where: { cartId: cart.id },
        });
        if (remainingSuppliers === 0) {
            await this.prisma.cart.update({
                where: { id: cart.id },
                data: { isDeleted: true, deletedAt: new Date() },
            });
            throw new NotFoundException(
                'Cart is now empty and has been deleted',
            );
        }

        await this.recalculateCartTotals(cart.id);
        const newCart = await this.getCartWithRelations(cart.id);
        return this.toCartResponseDto(newCart);
    }

    async checkoutCart(userId: string) {
        const { cart, buyer } = await this.getActiveCartByUserId(userId);

        if (cart.suppliers.length === 0)
            throw new BadRequestException('Cart is empty');

        // TODO: integrate with Tap payments gateway

        const checkoutId = uuidv4();

        const orders = await Promise.all(
            cart.suppliers.map((supplierCart) => {
                const finalPrice = supplierCart.supplierTotalPrice;
                return this.prisma.order.create({
                    data: {
                        checkoutId,
                        buyerId: buyer.id,
                        cartId: cart.id,
                        supplierId: supplierCart.supplierId,
                        finalPrice,
                    },
                });
            }),
        );

        await this.prisma.cart.update({
            where: { id: cart.id },
            data: { isBought: true },
        });

        return {
            message: 'Paid successfully',
            checkoutId,
            buyerId: buyer.id,
            cartId: cart.id,
            totalPaid: cart.cartTotal,
            orders,
        };
    }

    /** --- Recalculate totals --- */
    private async recalculateCartTotals(cartId: string) {
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

    /** --- Fetch cart with relations --- */
    private async getCartWithRelations(cartId: string) {
        return this.prisma.cart.findFirst({
            where: { id: cartId },
            include: {
                suppliers: {
                    include: {
                        cartItems: { include: { product: true } },
                        supplier: true,
                    },
                },
                buyer: { include: { user: true } },
            },
        });
    }
}
