import {
    BadRequestException,
    ForbiddenException,
    Injectable,
    NotFoundException,
} from '@nestjs/common';
import { BidService } from 'src/bid/bid.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { SupplierService } from 'src/supplier/supplier.service';
import { CreateOfferDto } from './dtos/createOffer.dto';
import { OfferResponseDto } from './dtos/offerResponse.dto';
import {
    BidStatus,
    NotificationEntityType,
    NotificationType,
    OfferStatus,
} from '@prisma/client';
import { NotificationService } from 'src/notification/notification.service';

@Injectable()
export class OfferService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly supplierService: SupplierService,
        private readonly bidService: BidService,
        private readonly notificationService: NotificationService,
    ) {}

    async toOfferResponseDto(offer: any): Promise<OfferResponseDto> {
        if (
            !offer.supplier ||
            !offer.supplier.user ||
            !offer.bid ||
            !offer.bid.buyer ||
            !offer.bid.buyer.user ||
            !offer.bid.bueyr.card
        ) {
            offer = await this.prisma.offer.findUnique({
                where: { id: offer.offerId },
                include: {
                    supplier: { include: { user: true } },
                    bid: {
                        include: {
                            buyer: { include: { user: true, card: true } },
                        },
                    },
                },
            });
        }

        const dto = new OfferResponseDto();

        dto.offerId = offer.offerId;
        dto.proposedAmount = offer.proposedAmount;
        dto.expectedCompletionTime = offer.expectedCompletionTime;
        dto.offerDetails = offer.offerDetails;
        dto.executionDetails = offer.executionDetails;
        dto.notes = offer.notes;
        dto.status = offer.status;
        dto.createdAt = offer.createdAt;

        // Nested mappings
        dto.supplier = await this.supplierService.toSupplierResponseDTO(
            offer.supplier.user,
            offer.supplier,
        );
        dto.bid = await this.bidService.toBidResponseDto(offer.bid);

        return dto;
    }

    async getOfferById(offerId: string): Promise<OfferResponseDto> {
        const offer = await this.prisma.offer.findUnique({
            where: { id: offerId },
            include: {
                supplier: {
                    include: { user: true },
                },
                bid: {
                    include: {
                        buyer: { include: { user: true, card: true } },
                    },
                },
            },
        });
        if (!offer) {
            throw new NotFoundException('Offer not found');
        }
        return this.toOfferResponseDto(offer);
    }

    async getOffersForBid(
        userId: string,
        bidId: string,
    ): Promise<OfferResponseDto[]> {
        // Get buyer object
        const buyer = await this.prisma.buyer.findUnique({
            where: { userId },
            include: { user: true },
        });
        if (!buyer) {
            throw new NotFoundException('Buyer not found');
        }

        // Get bid and verify ownership
        const bid = await this.prisma.bid.findUnique({
            where: { id: bidId },
            include: {
                buyer: true,
                offers: {
                    include: {
                        supplier: {
                            include: { user: true },
                        },
                    },
                },
            },
        });
        if (!bid) {
            throw new NotFoundException('Bid not found');
        }

        // Ensure this buyer owns the bid
        if (bid.buyerId !== buyer.id) {
            throw new ForbiddenException(
                'You are not authorized to view offers for this bid',
            );
        }

        // Check deadline
        const now = new Date();
        if (now < bid.submissionDeadline) {
            throw new BadRequestException(
                "You can't view the offers before the submission deadline arrives",
            );
        }

        // Convert offers to DTOs
        const offersDtos: OfferResponseDto[] = [];
        for (const offer of bid.offers) {
            const dto = await this.toOfferResponseDto({
                ...offer,
                bid,
            });
            offersDtos.push(dto);
        }
        return offersDtos;
    }

    async createOffer(
        userId: string,
        dto: CreateOfferDto,
    ): Promise<OfferResponseDto> {
        // 1. Validate supplier existence
        const supplier = await this.prisma.supplier.findUnique({
            where: { userId },
            include: { user: true },
        });
        if (!supplier) {
            throw new NotFoundException('Supplier not found');
        }

        // 2. Validate bid existence
        const bid = await this.prisma.bid.findUnique({
            where: { id: dto.bidId },
            include: { buyer: { include: { user: true } } },
        });
        if (!bid) {
            throw new NotFoundException('Bid not found');
        }

        // 3. Ensure bid is still open (before submission deadline)
        const now = new Date();
        if (now > bid.submissionDeadline || bid.status === BidStatus.CLOSED) {
            throw new BadRequestException(
                'Cannot submit offer: submission deadline has passed',
            );
        }

        // 4. Ensure supplier didn’t already submit an offer for this bid
        const existingOffer = await this.prisma.offer.findFirst({
            where: {
                bidId: dto.bidId,
                supplierId: supplier.id,
            },
        });
        if (existingOffer) {
            throw new BadRequestException(
                'You have already submitted an offer for this bid',
            );
        }

        // 5. Create offer
        const newOffer = await this.prisma.offer.create({
            data: {
                bidId: dto.bidId,
                supplierId: supplier.id,
                proposedAmount: dto.proposedAmount,
                expectedCompletionTime: new Date(dto.expectedCompletionTime),
                offerDetails: dto.offerDetails,
                executionDetails: dto.executionDetails,
                notes: dto.notes ?? null,
                status: OfferStatus.PENDING,
            },
            include: {
                supplier: { include: { user: true } },
                bid: {
                    include: { buyer: { include: { user: true, card: true } } },
                },
            },
        });

        //TODO: 6. Create preinvocie

        // 7. Send a notification for the buyer
        await this.notificationService.createNotification({
            senderUserId: newOffer.supplier.userId,
            receiverUserId: newOffer.bid.buyer.userId,
            type: NotificationType.NEW_OFFER,
            title: 'New Offer!',
            content: `Your bid ${newOffer.bid.bidName} got a new offer from ${newOffer.supplier.user.businessName}`,
            entityId: newOffer.id,
            entityType: NotificationEntityType.OFFER,
        });

        // 8. Return mapped response DTO
        return this.toOfferResponseDto(newOffer);
    }

    async updateOfferStatus(
        userId: string,
        offerId: string,
        status: OfferStatus,
    ): Promise<OfferResponseDto> {
        // 1. Validate buyer
        const buyer = await this.prisma.buyer.findUnique({
            where: { userId },
        });
        if (!buyer) {
            throw new NotFoundException('Buyer not found');
        }

        // 2. Find offer (include bid for ownership validation)
        const offer = await this.prisma.offer.findUnique({
            where: { id: offerId },
            include: {
                bid: true,
                supplier: { include: { user: true } },
            },
        });
        if (!offer) {
            throw new NotFoundException(`Offer with ID ${offerId} not found`);
        }

        // 3. Ensure offer’s bid belongs to this buyer
        if (offer.bid.buyerId !== buyer.id) {
            throw new ForbiddenException(
                'You are not authorized to modify offers for this bid',
            );
        }

        // 4. Ensure offer is still pending
        if (offer.status !== OfferStatus.PENDING) {
            throw new BadRequestException(
                'Only offers with pending status can be updated',
            );
        }

        // 5. Update offer
        const updatedOffer = await this.prisma.offer.update({
            where: { id: offerId },
            data: { status },
            include: {
                bid: {
                    include: { buyer: { include: { user: true, card: true } } },
                },
                supplier: { include: { user: true } },
            },
        });

        //TODO: 6. Upgrade preinvoice in case of accepted, otherwise mark preinvocie status as failed

        // 7. Send a notification for the supplier
        await this.notificationService.createNotification({
            senderUserId: updatedOffer.bid.buyer.userId,
            receiverUserId: updatedOffer.supplier.userId,
            type: NotificationType.BID_STATUS_CHANGED,
            title: 'Offer Status Changed!',
            content: `Your offer ${updatedOffer.id} got ${updatedOffer.status}`,
            entityId: updatedOffer.id,
            entityType: NotificationEntityType.OFFER,
        });

        // 8. Mark other offers of the same bid as DECLINED automatically

        //TODO: 9. Mark preinvocies status as failed for other participant suppliers

        // 10. Send notifications for declined suppliers

        // 11. Return dto
        return this.toOfferResponseDto(updatedOffer);
    }
}
