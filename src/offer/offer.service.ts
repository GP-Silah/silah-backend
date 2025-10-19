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
    InvoiceTermsOfPayment,
    NotificationEntityType,
    NotificationType,
    OfferStatus,
    PreInvoiceStatus,
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
        const dto = new OfferResponseDto();

        dto.offerId = offer.id;
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
                buyer: { include: { user: true, card: true } },
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
        bidId: string,
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
            where: { id: bidId },
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
                bidId: bidId,
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
                bidId,
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

        // 6. Create pre-invoice for the offer
        const preInvoice = await this.prisma.preInvoice.create({
            data: {
                offerId: newOffer.id, // link pre-invoice to this offer
                buyerId: newOffer.bid.buyerId, // the buyer of the bid
                supplierId: newOffer.supplierId, // the supplier creating the offer
                productId: null,
                amount: dto.proposedAmount, // amount based on the offer
                status: PreInvoiceStatus.PENDING, // initial status
            },
        });

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

        // 6. Upgrade preinvoice in case of accepted, otherwise mark preinvocie status as failed
        // Get the pre-invoice of the updated offer
        const offerPreInvoice = await this.prisma.preInvoice.findUnique({
            where: { offerId: updatedOffer.id },
        });

        if (offerPreInvoice) {
            if (status === OfferStatus.ACCEPTED) {
                // 1. Create an actual invoice based on the pre-invoice
                const newInvoice = await this.prisma.invoice.create({
                    data: {
                        buyerId: offerPreInvoice.buyerId,
                        supplierId: offerPreInvoice.supplierId,
                        deliveryDate: updatedOffer.expectedCompletionTime,
                        termsOfPayment: InvoiceTermsOfPayment.FULL,
                        uponDeliveryAmount: offerPreInvoice.amount,
                        amount: offerPreInvoice.amount,
                        notesAndTerms: `System Note: This invoice was automatically created because the offer (${updatedOffer.id}) from supplier "${updatedOffer.supplier.user.businessName}" for your bid "${updatedOffer.bid.bidName}" was accepted.`,
                        preInvoice: { connect: { id: offerPreInvoice.id } },
                    },
                });

                // 2. Update the pre-invoice to link it to the newly created invoice and mark it successful
                await this.prisma.preInvoice.update({
                    where: { id: offerPreInvoice.id },
                    data: {
                        status: PreInvoiceStatus.SUCCESSFUL,
                        invoiceId: newInvoice.id,
                    },
                });
            } else {
                // Offer declined → mark pre-invoice as failed
                await this.prisma.preInvoice.update({
                    where: { id: offerPreInvoice.id },
                    data: { status: PreInvoiceStatus.FAILED },
                });
            }
        }

        // 7. Notify the supplier about their offer’s status
        await this.notificationService.createNotification({
            senderUserId: updatedOffer.bid.buyer.userId,
            receiverUserId: updatedOffer.supplier.userId,
            type: NotificationType.BID_STATUS_CHANGED,
            title: 'Offer Status Changed!',
            content: `Your offer ${updatedOffer.id} got ${updatedOffer.status.toLowerCase()}`,
            entityId: updatedOffer.id,
            entityType: NotificationEntityType.OFFER,
        });

        // 8. If accepted -> decline all other offers automatically
        let declinedOffersInfo: {
            offerId: string;
            supplierUserId: string;
            supplierName: string;
        }[] = [];

        if (status === OfferStatus.ACCEPTED) {
            // Get other offers for the same bid
            const otherOffers = await this.prisma.offer.findMany({
                where: {
                    bidId: updatedOffer.bidId,
                    NOT: { id: offerId },
                    status: OfferStatus.PENDING,
                },
                include: {
                    supplier: { include: { user: true } },
                },
            });

            if (otherOffers.length > 0) {
                // Decline them in one go
                await this.prisma.offer.updateMany({
                    where: {
                        id: { in: otherOffers.map((o) => o.id) },
                    },
                    data: { status: OfferStatus.DECLINED },
                });

                // Collect info for later notification use
                declinedOffersInfo = otherOffers.map((offer) => ({
                    offerId: offer.id,
                    supplierUserId: offer.supplier.userId,
                    supplierName: offer.supplier.user.name,
                }));
            }

            // 9. Fail all other pre-invoices of declined offers automatically
            if (declinedOffersInfo.length > 0) {
                const otherPreInvoices = await this.prisma.preInvoice.findMany({
                    where: {
                        offerId: {
                            in: declinedOffersInfo.map((o) => o.offerId),
                        },
                    },
                });

                await this.prisma.preInvoice.updateMany({
                    where: {
                        id: { in: otherPreInvoices.map((pi) => pi.id) },
                    },
                    data: { status: PreInvoiceStatus.FAILED },
                });
            }
        }

        // 10. Send notifications for declined suppliers (batched)
        await Promise.all(
            declinedOffersInfo.map((declined) =>
                this.notificationService.createNotification({
                    senderUserId: updatedOffer.bid.buyer.userId,
                    receiverUserId: declined.supplierUserId,
                    type: NotificationType.BID_STATUS_CHANGED,
                    title: 'Offer Declined',
                    content: `Your offer ${declined.offerId} has been declined because another offer was accepted.`,
                    entityId: declined.offerId,
                    entityType: NotificationEntityType.OFFER,
                }),
            ),
        );

        // 11. Return dto
        return this.toOfferResponseDto(updatedOffer);
    }
}
