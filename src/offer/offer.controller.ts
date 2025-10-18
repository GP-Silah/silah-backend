import {
    BadRequestException,
    Body,
    Controller,
    Get,
    Param,
    Patch,
    Post,
    Query,
    Req,
    UseGuards,
} from '@nestjs/common';
import { OfferService } from './offer.service';
import { ApiTags } from '@nestjs/swagger';
import { ApiDocsJwtAuthGuard } from 'src/auth/decorators/jwt-auth-guard.docs';
import { ApiDocsRolesGuard } from 'src/auth/decorators/roles-guard.docs';
import { ApiDocsVerifiedGuard } from 'src/auth/decorators/verified-guard.docs';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { UserRole } from 'src/enums/userRole.enum';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { VerifiedGuard } from 'src/auth/guards/verified.guard';
import { Request } from 'express';
import { CreateOfferDto } from './dtos/createOffer.dto';
import { OfferStatus } from '@prisma/client';

@ApiTags('Offers')
@Controller('offers')
export class OfferController {
    constructor(private readonly offerService: OfferService) {}

    @Get(':id')
    async getOfferById(@Param('id') offerId: string) {
        return this.offerService.getOfferById(offerId);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @Get('bid/:id')
    async getOffersForBid(@Req() req: Request, @Param('id') bidId: string) {
        const userId = req.tokenData!.sub;
        return this.offerService.getOffersForBid(userId, bidId);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @Post()
    async createOffer(@Req() req: Request, @Body() dto: CreateOfferDto) {
        const userId = req.tokenData!.sub;
        return this.offerService.createOffer(userId, dto);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @Patch(':id')
    async updateOfferStatus(
        @Req() req: Request,
        @Param('id') offerId: string,
        @Query('status') status: string,
    ) {
        const newStatus = status.toUpperCase();
        const allowedStatuses = [
            OfferStatus.ACCEPTED,
            OfferStatus.DECLINED,
        ] as const;
        if (!(allowedStatuses as readonly string[]).includes(newStatus)) {
            throw new BadRequestException(
                `Invalid status. Allowed values: ${allowedStatuses.join(', ')}`,
            );
        }
        const userId = req.tokenData!.sub;
        return this.offerService.updateOfferStatus(
            userId,
            offerId,
            newStatus as OfferStatus,
        );
    }
}
