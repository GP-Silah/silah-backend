import { UserService } from 'src/user/user.service';
import { Injectable, NotFoundException } from '@nestjs/common';
import { BuyerResponseDto } from './dtos/buyerResponse.dto';
import { CardDetailsDto } from './dtos/cardDetails.dto';
import { PrismaService } from 'src/prisma/prisma.service';
import { TapPaymentsService } from 'src/tap-payments/tap-payments.service';
import { CreateCardDto } from './dtos/createCard.dto';
import { WishlistItemResponseDto } from './dtos/wishlistItemResponse.dto';
import { ItemType } from '@prisma/client';
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

    async getCurrentBuyerData(email: string): Promise<BuyerResponseDto> {
        const user = await this.prisma.user.findUnique({
            // currently the bueyr doesn't have any unique data, thus calling the user table only is enough
            where: { email },
            include: {
                buyer: {
                    select: {
                        card: true,
                    },
                },
            },
        });
        const cardEntity = user?.buyer?.card;
        const userData = await this.userService.toUserResponseDTO(user!);
        const cardData: CardDetailsDto | null = cardEntity
            ? {
                  id: cardEntity.id,
                  tapCardId: cardEntity.tapCardId,
                  cardHolderName: cardEntity.cardHolderName,
                  last4: cardEntity.last4,
                  brand: cardEntity.brand,
                  expMonth: cardEntity.expMonth,
                  expYear: cardEntity.expYear,
              }
            : null;
        return {
            user: userData,
            card: cardData ?? null,
        } as BuyerResponseDto;
    }

    async getCurrentBuyerCard(email: string): Promise<CardDetailsDto | null> {
        const user = await this.prisma.user.findUnique({
            where: { email },
            include: {
                buyer: {
                    select: {
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

    async saveOrReplaceCurrentBuyerCard(
        userId: string,
        createCardDto: CreateCardDto,
    ) {
        // Find user
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
            include: {
                buyer: { include: { card: true } },
            },
        });

        if (!user) {
            throw new NotFoundException('User not found');
        }

        // Auto-create Buyer if missing
        let buyer = user.buyer;
        if (!buyer) {
            buyer = await this.prisma.buyer.create({
                data: { userId: user.id },
                include: { card: true },
            });
        }

        const existingCard = buyer.card;

        if (existingCard) {
            // Delete from Tap
            await this.tapPaymentsService.deleteCard(
                user.tapCustomerId,
                existingCard.tapCardId,
            );
            // Delete from DB
            await this.prisma.card.delete({
                where: { id: existingCard.id },
            });
        }

        console.log('Creating card in Tap with token:', createCardDto.tokenId);
        // Create a minimal charge to save the card
        const charge = await this.tapPaymentsService.createCharge(
            createCardDto.tokenId,
            {
                first_name: user.name,
                email: user.email,
            },
        );
        console.log('Charge created:', charge.id);
        console.log(charge);

        console.log('Creating card in Tap with card:', createCardDto.cardId);
        // Fetch full card info from Tap using token
        const cardInfo = await this.tapPaymentsService.getCard(
            user.tapCustomerId,
            createCardDto.cardId,
        );

        // Save non-sensitive info in DB
        const savedCard = await this.prisma.card.create({
            data: {
                tapCardId: cardInfo.id,
                brand: cardInfo.brand,
                last4: cardInfo.last_four,
                expMonth: cardInfo.exp_month,
                expYear: cardInfo.exp_year,
                cardHolderName: cardInfo.name,
                buyer: {
                    connect: { id: buyer.id },
                },
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
            } as CardDetailsDto,
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

                    if (!product) return null;

                    const productDto =
                        await this.productService.toProductResponseDto(
                            product,
                            targetLang,
                        );

                    return {
                        itemId: entry.itemId,
                        itemType: ItemType.PRODUCT,
                        product: productDto,
                    };
                } else {
                    const service = await this.prisma.service.findUnique({
                        where: { id: entry.itemId },
                        include: {
                            category: true,
                            supplier: { include: { user: true } },
                        },
                    });

                    if (!service) return null;

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
        const product = await this.prisma.product.findUnique({
            where: { id: itemId },
        });
        if (product) {
            itemType = ItemType.PRODUCT;
        } else {
            const service = await this.prisma.service.findUnique({
                where: { id: itemId },
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
