import { Injectable } from '@nestjs/common';
import { BuyerService } from 'src/buyer/buyer.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateBidDto } from './dtos/createBid.dto';
import {
    Bid,
    BidExpectedResponseTime,
    BidStatus,
    Buyer,
    Card,
    User,
} from '@prisma/client';
import { BidResponseDto } from './dtos/bidResponse.dto';
import { BuyerResponseDto } from 'src/buyer/dtos/buyerResponse.dto';

@Injectable()
export class BidService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly buyerService: BuyerService,
    ) {}

    /**
     * Converts a Prisma Bid entity into a BidResponseDto.
     * Includes nested buyer data (converted to BuyerResponseDto).
     */
    async toBidResponseDto(
        bid: any & { buyer: Buyer & { user: User; card: Card } },
    ): Promise<BidResponseDto> {
        const buyerDto: BuyerResponseDto =
            await this.buyerService.toBuyerResponseDto(
                bid.buyer.user,
                bid.buyer,
            );

        return {
            bidId: bid.id,
            bidName: bid.bidName,
            mainActivity: bid.mainActivity,
            submissionDeadline: bid.submissionDeadline,
            expectedResponseTime:
                bid.expectedResponseTime as BidExpectedResponseTime,
            status: bid.status as BidStatus,
            buyer: buyerDto,
            createdAt: bid.createdAt,
        };
    }

    async getAllBids() {
        const bids = await this.prisma.bid.findMany({
            include: { buyer: { include: { user: true, card: true } } },
        });
        return Promise.all(bids.map((b) => this.toBidResponseDto(b)));
    }

    async getBidById(bidId: string) {}

    async getMyBids(userId: string) {}

    async createBid(userId: string, dto: CreateBidDto) {}
}
