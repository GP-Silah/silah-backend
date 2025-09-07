import { UserService } from 'src/user/user.service';
import { Injectable, NotFoundException } from '@nestjs/common';
import { BuyerResponseDto } from './dtos/buyerResponse.dto';
import { CardDetailsDto } from './dtos/cardDetails.dto';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class BuyerService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly userService: UserService,
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
            select: {
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

    async saveOrReplaceCurrentBuyerCard() {}

    async deleteCurrentBuyerCard() {}
}
