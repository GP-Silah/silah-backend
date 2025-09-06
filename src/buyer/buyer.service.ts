import { Injectable } from '@nestjs/common';
import { BuyerResponseDto } from './dtos/buyerResponse.dto';
import { CardDetailsDto } from './dtos/cardDetails.dto';

@Injectable()
export class BuyerService {
    async getCurrentBuyerData(): Promise<BuyerResponseDto> {
        //TODO: Implementation to fetch current buyer data
        const buyerData: BuyerResponseDto = {} as BuyerResponseDto;
        return buyerData;
    }

    async getCurrentBuyerCard(): Promise<CardDetailsDto> {
        //TODO: Implementation to fetch current buyer card details
        const cardData: CardDetailsDto = {} as CardDetailsDto;
        return cardData;
    }

    async deleteCurrentBuyerCard() {}
}
