import { UserService } from 'src/user/user.service';
import { Injectable, NotFoundException } from '@nestjs/common';
import { BuyerResponseDto } from './dtos/buyerResponse.dto';
import { CardDetailsDto } from './dtos/cardDetails.dto';
import { PrismaService } from 'src/prisma/prisma.service';
import { TapPaymentsService } from 'src/tap-payments/tap-payments.service';
import { CreateCardDto } from './dtos/createCard.dto';

@Injectable()
export class BuyerService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly userService: UserService,
        private readonly tapPaymentsService: TapPaymentsService,
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
}
