import { Injectable, NotFoundException } from '@nestjs/common';
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
            where: {
                submissionDeadline: {
                    gt: new Date(), // greater than now → deadline hasn't passed
                },
            },
            include: { buyer: { include: { user: true, card: true } } },
        });
        return Promise.all(bids.map((b) => this.toBidResponseDto(b)));
    }

    async getBidById(bidId: string) {
        const bid = await this.prisma.bid.findFirst({
            where: { id: bidId },
            include: { buyer: { include: { user: true, card: true } } },
        });
        if (!bid) {
            throw new NotFoundException(`Bid with ID ${bidId} not found`);
        }
        return this.toBidResponseDto(bid);
    }

    async getMyBids(userId: string): Promise<BidResponseDto[]> {
        const buyer = await this.prisma.buyer.findFirst({
            where: { userId },
        });
        if (!buyer) {
            throw new Error('Buyer not found');
        }
        const bids = await this.prisma.bid.findMany({
            where: { buyerId: buyer.id },
            include: { buyer: { include: { user: true, card: true } } },
            orderBy: { createdAt: 'desc' },
        });
        return Promise.all(bids.map((bid) => this.toBidResponseDto(bid)));
    }

    async createBid(
        userId: string,
        dto: CreateBidDto,
    ): Promise<BidResponseDto> {
        const buyer = await this.prisma.buyer.findFirst({
            where: { userId },
        });
        if (!buyer) {
            throw new Error('Buyer not found');
        }
        const bid = await this.prisma.bid.create({
            data: {
                buyerId: buyer.id,
                bidName: dto.bidName,
                mainActivity: dto.mainActivity,
                submissionDeadline: new Date(dto.submissionDeadline),
                expectedResponseTime: dto.expectedResponseTime,
            },
            include: { buyer: { include: { user: true, card: true } } },
        });
        return this.toBidResponseDto(bid);
    }

    async getBidsIJoined(userId: string): Promise<BidResponseDto[]> {
        const supplier = await this.prisma.supplier.findFirst({
            where: { userId },
        });
        if (!supplier) throw new NotFoundException('Supplier not found');
        const bids = await this.prisma.bid.findMany({
            where: {
                offers: { some: { supplierId: supplier.id } },
            },
            include: { buyer: { include: { user: true, card: true } } },
            orderBy: { createdAt: 'desc' },
        });
        return Promise.all(bids.map((b) => this.toBidResponseDto(b)));
    }
}
