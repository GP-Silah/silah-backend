import {
    Body,
    Controller,
    Delete,
    Get,
    Param,
    Patch,
    Put,
    Req,
    UseGuards,
} from '@nestjs/common';
import { BuyerService } from './buyer.service';
import { ApiTags } from '@nestjs/swagger';
import { BuyerResponseDto } from './dtos/buyerResponse.dto';
import { CardDetailsDto } from './dtos/cardDetails.dto';
import { ApiDocsJwtAuthGuard } from 'src/auth/decorators/jwt-auth-guard.docs';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { UserRole } from 'src/enums/userRole.enum';
import { Request } from 'express';
import { CreateCardStep1Dto, CreateCardStep2Dto } from './dtos/createCard.dto';
import { ApiDocsRolesGuard } from 'src/auth/decorators/roles-guard.docs';
import {
    ApiDocsDeleteCurrentBuyerCard,
    ApiDocsGetCurrentBuyerCard,
    ApiDocsGetCurrentBuyerData,
    ApiDocsGetCurrentBuyerWishlist,
    ApiDocsSaveOrReplaceCurrentBuyerCardStep1,
    ApiDocsSaveOrReplaceCurrentBuyerCardStep2,
    ApiDocsToggleWishlistItem,
} from './buyer.docs';
import { ApiDocsVerifiedGuard } from 'src/auth/decorators/verified-guard.docs';
import { VerifiedGuard } from 'src/auth/guards/verified.guard';

@ApiTags('Buyers')
@Controller('buyers')
export class BuyerController {
    constructor(private readonly buyerService: BuyerService) {}

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Get('me')
    @ApiDocsGetCurrentBuyerData()
    async getCurrentBuyerData(@Req() req: Request): Promise<BuyerResponseDto> {
        return this.buyerService.getCurrentBuyerData(req.tokenData!.email);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Get('me/card')
    @ApiDocsGetCurrentBuyerCard()
    async getCurrentBuyerCard(
        @Req() req: Request,
    ): Promise<CardDetailsDto | { message: string; card: null }> {
        const card = await this.buyerService.getCurrentBuyerCard(
            req.tokenData!.email,
        );
        if (!card) {
            return {
                message: 'No card found',
                card: null,
            };
        }
        return card as unknown as Promise<CardDetailsDto>;
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @Put('me/card')
    @ApiDocsSaveOrReplaceCurrentBuyerCardStep1()
    async saveOrReplaceCurrentBuyerCardStep1(
        @Req() req: Request,
        @Body() body: CreateCardStep1Dto,
    ) {
        return await this.buyerService.saveOrReplaceCurrentBuyerCardStep1(
            req.tokenData!.sub,
            body,
        );
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @Put('me/card/confirm')
    @ApiDocsSaveOrReplaceCurrentBuyerCardStep2()
    async saveOrReplaceCurrentBuyerCardStep2(
        @Req() req: Request,
        @Body() body: CreateCardStep2Dto,
    ) {
        return await this.buyerService.saveOrReplaceCurrentBuyerCardStep2(
            req.tokenData!.sub,
            body,
        );
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @Delete('me/card')
    @ApiDocsDeleteCurrentBuyerCard()
    async deleteCurrentBuyerCard(@Req() req: Request) {
        return this.buyerService.deleteCurrentBuyerCard(req.tokenData!.sub);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Get('me/wishlist')
    @ApiDocsGetCurrentBuyerWishlist()
    async getWishlist(@Req() req: Request) {
        const userId = req.tokenData!.sub;
        return this.buyerService.getWishlist(userId);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Patch('me/wishlist/:itemId')
    @ApiDocsToggleWishlistItem()
    async toggleWishlistItem(
        @Req() req: Request,
        @Param('itemId') itemId: string,
    ) {
        const userId = req.tokenData!.sub;
        return this.buyerService.toggleWishlistItem(userId, itemId);
    }
}
