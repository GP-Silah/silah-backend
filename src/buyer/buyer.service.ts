import { UserService } from 'src/user/user.service';
import {
    BadRequestException,
    Injectable,
    NotFoundException,
} from '@nestjs/common';
import { BuyerResponseDto } from './dtos/buyerResponse.dto';
import { CardDetailsDto } from './dtos/cardDetails.dto';
import { PrismaService } from 'src/prisma/prisma.service';
import { TapPaymentsService } from 'src/tap-payments/tap-payments.service';
import { CreateCardStep1Dto, CreateCardStep2Dto } from './dtos/createCard.dto';
import { WishlistItemResponseDto } from './dtos/wishlistItemResponse.dto';
import { Buyer, Card, ItemType, User } from '@prisma/client';
import { ProductService } from 'src/product/product.service';
import { ServiceService } from 'src/service/service.service';

@Injectable()
export class BuyerService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly userService: UserService,
        private readonly tapPaymentsService: TapPaymentsService,
        private readonly productService: ProductService,
        private readonly serviceService: ServiceService,
    ) {}

    async toBuyerResponseDto(
        user: User,
        buyer: Buyer & {
            card: Card | null;
        },
    ): Promise<BuyerResponseDto> {
        const userData = await this.userService.toUserResponseDTO(user);

        const cardData: CardDetailsDto | null = buyer.card
            ? {
                  id: buyer.card.id,
                  tapCardId: buyer.card.tapCardId,
                  cardHolderName: buyer.card.cardHolderName,
                  last4: buyer.card.last4,
                  brand: buyer.card.brand,
                  expMonth: buyer.card.expMonth,
                  expYear: buyer.card.expYear,
              }
            : null;

        return {
            buyerId: buyer.id,
            user: userData,
            card: cardData,
        };
    }

    async getCurrentBuyerData(email: string): Promise<BuyerResponseDto> {
        const user = await this.prisma.user.findUnique({
            where: { email },
            include: {
                buyer: {
                    include: { card: true },
                },
            },
        });

        if (!user || !user.buyer) {
            throw new NotFoundException('Buyer not found');
        }

        // Always use the mapper to avoid duplication
        return this.toBuyerResponseDto(user, user.buyer);
    }

    async getCurrentBuyerCard(email: string): Promise<CardDetailsDto | null> {
        const user = await this.prisma.user.findUnique({
            where: { email },
            include: {
                buyer: {
                    include: {
                        card: true,
                    },
                },
            },
        });
        if (!user || !user.buyer || !user.buyer.card) {
            return null;
        }
        const card = user.buyer.card;
        if (!card) {
            return null;
        }
        return {
            id: card.id,
            tapCardId: card.tapCardId,
            cardHolderName: card.cardHolderName,
            last4: card.last4,
            brand: card.brand,
            expMonth: card.expMonth,
            expYear: card.expYear,
        } as CardDetailsDto;
    }

    // STEP 1: initiate charge & redirect to OTP
    async saveOrReplaceCurrentBuyerCardStep1(
        userId: string,
        dto: CreateCardStep1Dto,
    ) {
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
            include: { buyer: { include: { card: true } } },
        });
        if (!user) throw new NotFoundException('User not found');

        // Auto-create buyer
        let buyer = user.buyer;
        if (!buyer) {
            buyer = await this.prisma.buyer.create({
                data: { userId: user.id },
                include: { card: true },
            });
        }

        // Delete existing card (Tap + DB)
        if (buyer.card) {
            await this.tapPaymentsService.deleteCard(
                user.tapCustomerId,
                buyer.card.tapCardId,
            );
            await this.prisma.card.delete({ where: { id: buyer.card.id } });
        }

        // Create charge
        const charge = await this.tapPaymentsService.createCharge(
            dto.tokenId,
            user.tapCustomerId,
            dto.redirectUrl,
        );

        return {
            transactionUrl: charge.transaction.url,
            chargeId: charge.id, // frontend must store this
        };
    }

    // STEP 2: after redirect, verify charge + save card
    async saveOrReplaceCurrentBuyerCardStep2(
        userId: string,
        dto: CreateCardStep2Dto,
    ) {
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
            include: { buyer: { include: { card: true } } },
        });
        if (!user) throw new NotFoundException('User not found');

        let buyer = user.buyer;
        if (!buyer) {
            buyer = await this.prisma.buyer.create({
                data: { userId: user.id },
                include: { card: true },
            });
        }

        // 1. Verify charge succeeded
        const charge = await this.tapPaymentsService.getCharge(dto.chargeId);
        if (!charge || !['CAPTURED', 'AUTHORIZED'].includes(charge.status)) {
            throw new BadRequestException(
                `Charge ${dto.chargeId} not successful. Status: ${charge?.status}`,
            );
        }

        await this.tapPaymentsService.validateCharge(charge);

        // 2. Safely extract saved card from charge
        const card = charge.card || charge.payment_agreement?.contract;
        if (!card) {
            throw new BadRequestException(
                'No card information found in the charge. Maybe payment failed or method is not a card.',
            );
        }

        // 3. Save in DB directly from charge.card
        const savedCard = await this.prisma.card.create({
            data: {
                tapCardId: card.id,
                brand: card.brand,
                last4: card.last_four || card.last4,
                expMonth: card.expiry?.month || card.exp_month,
                expYear: card.expiry?.year || card.exp_year,
                cardHolderName: card.name,
                buyer: { connect: { id: buyer.id } },
            },
        });

        return {
            message: 'Card saved successfully',
            card: {
                id: savedCard.id,
                tapCardId: savedCard.tapCardId,
                cardHolderName: savedCard.cardHolderName,
                last4: savedCard.last4,
                brand: savedCard.brand,
                expMonth: savedCard.expMonth,
                expYear: savedCard.expYear,
            },
        };
    }

    async deleteCurrentBuyerCard(userId: string) {
        // 1. Find buyer with their card
        const buyer = await this.prisma.buyer.findUnique({
            where: { userId },
            include: { card: true, user: true }, // include user because tapCustomerId is in user
        });

        if (!buyer || !buyer.card) {
            throw new NotFoundException('No card found for this buyer');
        }

        const { tapCardId } = buyer.card;
        const { tapCustomerId } = buyer.user;

        // 2. Call Tap to delete the card
        await this.tapPaymentsService.deleteCard(tapCustomerId, tapCardId);

        // 3. Remove card record from DB
        await this.prisma.card.delete({
            where: { id: buyer.card.id },
        });

        return { message: 'Card deleted successfully' };
    }

    async getWishlist(
        userId: string,
        targetLang?: 'ar' | 'en',
    ): Promise<WishlistItemResponseDto[]> {
        const buyer = await this.prisma.buyer.findUnique({ where: { userId } });
        if (!buyer) throw new NotFoundException('Buyer not found');

        const wishlistEntries = await this.prisma.wishlist.findMany({
            where: { buyerId: buyer.id },
        });

        const result: (WishlistItemResponseDto | null)[] = await Promise.all(
            wishlistEntries.map(async (entry) => {
                if (entry.itemType === ItemType.PRODUCT) {
                    const product = await this.prisma.product.findUnique({
                        where: { id: entry.itemId },
                        include: {
                            category: true,
                            supplier: { include: { user: true } },
                        },
                    });

                    if (!product || product.isDeleted) {
                        // auto-clean wishlist
                        await this.prisma.wishlist.delete({
                            where: { id: entry.id },
                        });
                        return null;
                    }

                    const productDto =
                        await this.productService.toProductResponseDto(
                            product,
                            targetLang,
                        );

                    return {
                        itemId: entry.itemId,
                        itemType: ItemType.PRODUCT,
                        product: productDto,
                        isAvailable: product.stock > 0,
                    };
                } else {
                    const service = await this.prisma.service.findUnique({
                        where: { id: entry.itemId },
                        include: {
                            category: true,
                            supplier: { include: { user: true } },
                        },
                    });

                    if (!service || service.isDeleted) {
                        // auto-clean wishlist
                        await this.prisma.wishlist.delete({
                            where: { id: entry.id },
                        });
                        return null;
                    }

                    const serviceDto =
                        await this.serviceService.toServiceResponseDto(
                            service,
                            targetLang,
                        );

                    return {
                        itemId: entry.itemId,
                        itemType: ItemType.SERVICE,
                        service: serviceDto,
                    };
                }
            }),
        );

        // Filter nulls and assert type
        return result.filter(
            (item): item is WishlistItemResponseDto => item !== null,
        );
    }

    async toggleWishlistItem(
        userId: string,
        itemId: string,
    ): Promise<{
        message: string;
        isAdded: boolean;
        updatedWishlist: WishlistItemResponseDto[];
    }> {
        // 1️⃣ Find the buyer
        const buyer = await this.prisma.buyer.findUnique({ where: { userId } });
        if (!buyer) throw new NotFoundException('Buyer not found');

        // 2️⃣ Determine item type
        let itemType: ItemType;
        const product = await this.prisma.product.findFirst({
            where: { id: itemId, isDeleted: false },
        });
        if (product) {
            itemType = ItemType.PRODUCT;
        } else {
            const service = await this.prisma.service.findFirst({
                where: { id: itemId, isDeleted: false },
            });
            if (service) {
                itemType = ItemType.SERVICE;
            } else {
                throw new NotFoundException('Item not found');
            }
        }

        // 3️⃣ Check if the wishlist entry exists
        const existing = await this.prisma.wishlist.findUnique({
            where: {
                buyerId_itemId_itemType: {
                    buyerId: buyer.id,
                    itemId,
                    itemType,
                },
            },
        });

        let message: string;
        let isAdded: boolean;

        if (existing) {
            // Remove from wishlist
            await this.prisma.wishlist.delete({ where: { id: existing.id } });
            message = 'Item removed from wishlist';
            isAdded = false;

            // Decrement wishlist count
            if (itemType === ItemType.PRODUCT) {
                await this.prisma.product.update({
                    where: { id: itemId },
                    data: { wishlistCount: { decrement: 1 } },
                });
            } else {
                await this.prisma.service.update({
                    where: { id: itemId },
                    data: { wishlistCount: { decrement: 1 } },
                });
            }
        } else {
            // Add to wishlist
            await this.prisma.wishlist.create({
                data: { buyerId: buyer.id, itemId, itemType },
            });
            message = 'Item added to wishlist';
            isAdded = true;

            // Increment wishlist count
            if (itemType === ItemType.PRODUCT) {
                await this.prisma.product.update({
                    where: { id: itemId },
                    data: { wishlistCount: { increment: 1 } },
                });
            } else {
                await this.prisma.service.update({
                    where: { id: itemId },
                    data: { wishlistCount: { increment: 1 } },
                });
            }
        }

        // 4️⃣ Return the updated wishlist
        return {
            message,
            isAdded,
            updatedWishlist: await this.getWishlist(userId),
        };
    }
}
