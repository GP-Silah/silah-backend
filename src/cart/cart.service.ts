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
import { TapPaymentsService } from 'src/tap-payments/tap-payments.service';
import { CheckoutCartDto } from './dtos/checkoutCart.dto';

@Injectable()
export class CartService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly translationService: TranslationService,
        private readonly tapPaymentsService: TapPaymentsService,
    ) {}

    async toCartResponseDto(cart: any): Promise<CartResponseDto> {
        const lang = cart.user?.preferredLanguage ?? 'EN'; // default if user missing
        const targetLang = ['ar', 'en'].includes(lang.toLowerCase())
            ? lang.toLowerCase()
            : 'en'; // fallback to English

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
                    deliveryFee: s.supplier?.deliveryFees ?? 0,
                    subTotal: s.subTotal,
                    supplierTotalPrice: s.supplierTotalPrice,
                    cartItems: await Promise.all(
                        s.cartItems.map(async (item: any) => {
                            // Translate product name if needed
                            const productName =
                                targetLang === 'en'
                                    ? item.product.name
                                    : await this.translationService.translateText(
                                          item.product.name,
                                          targetLang,
                                      );

                            // --- mark out-of-stock items ---
                            const isAvailable =
                                item.product.stock >= item.quantity;

                            return {
                                cartItemId: item.id,
                                productId: item.productId,
                                productName,
                                productPrice: item.product.price,
                                quantity: item.quantity,
                                itemTotalPrice: item.itemTotalPrice,
                                isAvailable,
                            };
                        }),
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

        // Get product and supplier together
        const product = await this.prisma.product.findUnique({
            where: { id: dto.productId },
            include: { supplier: true },
        });

        if (!product) throw new NotFoundException('Product not found');
        if (!product.supplier || product.supplier.isDeleted) {
            throw new BadRequestException(
                'Supplier for this product not found',
            );
        }

        if (product.stock < dto.quantity) {
            throw new BadRequestException(
                `Only ${product.stock} units available in stock`,
            );
        }

        // --- Validate quantity against case quantity and min/max order quantities ---
        if (dto.quantity % product.caseQuantity !== 0) {
            throw new BadRequestException(
                `Quantity must be in multiples of ${product.caseQuantity}`,
            );
        }
        if (dto.quantity < product.minOrderQuantity) {
            throw new BadRequestException(
                `Quantity must be at least the minimum order quantity: ${product.minOrderQuantity}`,
            );
        }
        if (
            product.maxOrderQuantity &&
            dto.quantity > product.maxOrderQuantity
        ) {
            throw new BadRequestException(
                `Quantity must not exceed the maximum order quantity: ${product.maxOrderQuantity}`,
            );
        }

        const supplier = product.supplier;

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

        // Get or create CartBySupplier
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

        // Add or update CartItem
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

        // Recalculate CartBySupplier totals immediately
        const newSubTotalAgg = await this.prisma.cartItem.aggregate({
            _sum: { itemTotalPrice: true },
            where: { cartBySupplierId: cartBySupplier.id },
        });
        const newSubTotal = newSubTotalAgg._sum.itemTotalPrice ?? 0;

        // Recalculate CartBySupplier totals
        await this.prisma.cartBySupplier.update({
            where: { id: cartBySupplier.id },
            data: {
                subTotal: newSubTotal,
                supplierTotalPrice: newSubTotal + (supplier?.deliveryFees ?? 0),
            },
        });

        // Recalculate overall cart totals
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
            include: {
                product: true,
                cartBySupplier: {
                    include: {
                        supplier: true,
                    },
                },
            },
        });

        if (!item || item.cartBySupplier.cartId !== cart.id) {
            throw new NotFoundException('Item not found in this cart');
        }

        if (item.product.stock < newQuantity) {
            throw new BadRequestException(
                `Only ${item.product.stock} units available in stock`,
            );
        }

        // --- Validate new quantity against case quantity and min/max ---
        if (newQuantity % item.product.caseQuantity !== 0) {
            throw new BadRequestException(
                `Quantity must be in multiples of ${item.product.caseQuantity}`,
            );
        }
        if (newQuantity < item.product.minOrderQuantity) {
            throw new BadRequestException(
                `Quantity must be at least the minimum order quantity: ${item.product.minOrderQuantity}`,
            );
        }
        if (
            item.product.maxOrderQuantity &&
            newQuantity > item.product.maxOrderQuantity
        ) {
            throw new BadRequestException(
                `Quantity must not exceed the maximum order quantity: ${item.product.maxOrderQuantity}`,
            );
        }

        // Update item
        await this.prisma.cartItem.update({
            where: { id: itemId },
            data: {
                quantity: newQuantity,
                itemTotalPrice: newQuantity * item.product.price,
            },
        });

        const cartBySupplier = item.cartBySupplier;

        // Recalculate CartBySupplier totals
        const newSubTotalAgg = await this.prisma.cartItem.aggregate({
            _sum: { itemTotalPrice: true },
            where: { cartBySupplierId: cartBySupplier.id },
        });
        const newSubTotal = newSubTotalAgg._sum.itemTotalPrice ?? 0;

        // Recalculate CartBySupplier totals
        await this.prisma.cartBySupplier.update({
            where: { id: cartBySupplier.id },
            data: {
                subTotal: newSubTotal,
                supplierTotalPrice:
                    newSubTotal + (cartBySupplier.supplier?.deliveryFees ?? 0),
            },
        });

        // Recalculate overall cart totals
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

    async deleteCart(userId: string): Promise<{ message: string }> {
        const { cart } = await this.getActiveCartByUserId(userId);
        await this.prisma.cart.update({
            where: { id: cart.id },
            data: { isDeleted: true, deletedAt: new Date() },
        });
        return {
            message: 'Cart deleted successfully',
        };
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

    async checkoutCart(userId: string, dto: CheckoutCartDto) {
        const { cart, buyer } = await this.getActiveCartByUserId(userId);

        if (cart.suppliers.length === 0) {
            throw new BadRequestException('Cart is empty');
        }

        // --- Check stock before proceeding ---
        for (const supplierCart of cart.suppliers) {
            for (const item of supplierCart.cartItems) {
                if (item.product.stock < item.quantity) {
                    throw new BadRequestException(
                        `Product "${item.product.name}" is out of stock. Remove it from the cart to proceed.`,
                    );
                }
            }
        }

        if (!buyer.card) {
            throw new BadRequestException('No saved card found for this buyer');
        }
        if (!buyer.user.tapCustomerId)
            throw new BadRequestException('Missing Tap customer ID');

        // --- Path 1: Confirm existing charge if chargeId is provided ---
        if (dto.chargeId) {
            const charge = await this.tapPaymentsService.getCharge(
                dto.chargeId,
            );

            if (['CAPTURED', 'AUTHORIZED'].includes(charge.status)) {
                // Create orders + reduce stock
                const orders = await Promise.all(
                    cart.suppliers.map(async (supplierCart) => {
                        const order = await this.prisma.order.create({
                            data: {
                                tapChargeId: charge.id,
                                buyerId: buyer.id,
                                cartId: cart.id,
                                supplierId: supplierCart.supplierId,
                                finalPrice: supplierCart.supplierTotalPrice,
                            },
                        });

                        // Reduce stock for each product in the supplier cart
                        await Promise.all(
                            supplierCart.cartItems.map((item) =>
                                this.prisma.product.update({
                                    where: { id: item.product.id },
                                    data: {
                                        stock:
                                            item.product.stock - item.quantity,
                                    },
                                }),
                            ),
                        );

                        return order;
                    }),
                );

                await this.prisma.cart.update({
                    where: { id: cart.id },
                    data: { isBought: true },
                });

                return {
                    message: 'Paid successfully',
                    tapChargeId: charge.id,
                    buyerId: buyer.id,
                    cartId: cart.id,
                    totalPaid: cart.cartTotal,
                    orders,
                };
            }

            throw new BadRequestException(
                `Charge not successful yet. Status: ${charge.status}`,
            );
        }

        // --- Path 2: Create new charge if no chargeId ---
        const token = await this.tapPaymentsService.createTokenFromSavedCard(
            buyer.user.tapCustomerId,
            buyer.card.tapCardId,
        );

        const charge = await this.tapPaymentsService.payWithSavedCard(
            buyer.user.tapCustomerId,
            token.id,
            buyer.card.tapCardId,
            cart.cartTotal, // major units
            'http://localhost:5137/payment/cart/callback', // TODO: real redirect URL
        );

        // --- Redirect for 3DS if necessary ---
        if (charge.status === 'INITIATED' && charge.transaction?.url) {
            return {
                message: 'Redirect for authentication',
                redirectUrl: charge.transaction.url,
                chargeId: charge.id,
            };
        }

        // --- Complete checkout if charge captured/authorized ---
        if (['CAPTURED', 'AUTHORIZED'].includes(charge.status)) {
            const orders = await Promise.all(
                cart.suppliers.map(async (supplierCart) => {
                    const order = await this.prisma.order.create({
                        data: {
                            tapChargeId: charge.id,
                            buyerId: buyer.id,
                            cartId: cart.id,
                            supplierId: supplierCart.supplierId,
                            finalPrice: supplierCart.supplierTotalPrice,
                        },
                    });

                    // Reduce stock for each product
                    await Promise.all(
                        supplierCart.cartItems.map((item) =>
                            this.prisma.product.update({
                                where: { id: item.product.id },
                                data: {
                                    stock: item.product.stock - item.quantity,
                                },
                            }),
                        ),
                    );

                    return order;
                }),
            );

            await this.prisma.cart.update({
                where: { id: cart.id },
                data: { isBought: true },
            });

            return {
                message: 'Paid successfully',
                tapChargeId: charge.id,
                buyerId: buyer.id,
                cartId: cart.id,
                totalPaid: cart.cartTotal,
                orders,
            };
        }

        throw new BadRequestException(
            `Payment failed. Charge status: ${charge.status}`,
        );
    }

    /** --- UTILITY: Get active cart for a buyer --- */
    private async getActiveCartByUserId(userId: string) {
        const buyer = await this.prisma.buyer.findUnique({
            where: { userId },
            include: { user: true, card: true },
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
                buyer: { include: { user: true } },
            },
        });

        if (!cart)
            throw new NotFoundException('No active cart found for this buyer');

        return { cart, buyer };
    }

    /** --- UTILITY: Recalculate totals --- */
    private async recalculateCartTotals(cartId: string) {
        // Fetch cartBySupplier along with the supplier row
        const cartSuppliers = await this.prisma.cartBySupplier.findMany({
            where: { cartId },
            include: { supplier: true },
        });

        const productsTotal = cartSuppliers.reduce(
            (sum, s) => sum + s.subTotal,
            0,
        );
        const deliveryFees = cartSuppliers.reduce(
            (sum, s) => sum + (s.supplier?.deliveryFees ?? 0),
            0,
        );
        const cartTotal = productsTotal + deliveryFees;

        await this.prisma.cart.update({
            where: { id: cartId },
            data: { productsTotal, deliveryFees, cartTotal },
        });

        // Also update each cartBySupplier total price correctly
        await Promise.all(
            cartSuppliers.map(async (s) => {
                await this.prisma.cartBySupplier.update({
                    where: { id: s.id },
                    data: {
                        supplierTotalPrice:
                            s.subTotal + (s.supplier?.deliveryFees ?? 0),
                    },
                });
            }),
        );
    }

    /** --- UTILITY: Fetch cart with relations --- */
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
