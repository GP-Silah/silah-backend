import {
    Body,
    Controller,
    Get,
    Param,
    Post,
    Req,
    UseGuards,
} from '@nestjs/common';
import { BidService } from './bid.service';
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
import { CreateBidDto } from './dtos/createBid.dto';
import {
    ApiDocsCreateBid,
    ApiDocsGetAllBids,
    ApiDocsGetBidById,
    ApiDocsGetBidsIJoined,
    ApiDocsGetMyBids,
} from './bid.docs';

@ApiTags('Bids')
@Controller('bids')
export class BidController {
    constructor(private readonly bidService: BidService) {}

    @Get()
    @ApiDocsGetAllBids()
    async getAllBids() {
        return this.bidService.getAllBids();
    }

    @Get(':id')
    @ApiDocsGetBidById()
    async getBidById(@Param('id') bidId: string) {
        return this.bidService.getBidById(bidId);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @Get('created/me')
    @ApiDocsGetMyBids()
    async getMyBids(@Req() req: Request) {
        const userId = req.tokenData!.sub;
        return this.bidService.getMyBids(userId);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @Post()
    @ApiDocsCreateBid()
    async createBid(@Req() req: Request, @Body() dto: CreateBidDto) {
        const userId = req.tokenData!.sub;
        return this.bidService.createBid(userId, dto);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @Get('joined/me')
    @ApiDocsGetBidsIJoined()
    async getBidsIJoined(@Req() req: Request) {
        const userId = req.tokenData!.sub;
        return this.bidService.getBidsIJoined(userId);
    }
}
