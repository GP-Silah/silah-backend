import {
    Body,
    Controller,
    Delete,
    Get,
    Param,
    Patch,
    Post,
    Put,
    Req,
    UseGuards,
} from '@nestjs/common';
import { BuyerService } from './buyer.service';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { BuyerResponseDto } from './dtos/buyerResponse.dto';
import { CardDetailsDto } from './dtos/cardDetails.dto';
import { ApiJwtAuthGuard } from 'src/auth/decorators/api-jwt-auth-guard.docs';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { UserRole } from 'src/enums/userRole.enum';
import { Request } from 'express';
import { CreateCardDto } from './dtos/createCard.dto';
import { ApiRolesGuard } from 'src/auth/decorators/api-roles-guard.docs';
import {
    ApiDocsDeleteCurrentBuyerCard,
    ApiDocsGetCurrentBuyerCard,
    ApiDocsGetCurrentBuyerData,
    ApiDocsGetCurrentBuyerWishlist,
    ApiDocsSaveOrReplaceCurrentBuyerCard,
    ApiDocsToggleWishlistItem,
} from './buyer.docs';

@ApiTags('Buyers')
@Controller('buyers')
export class BuyerController {
    constructor(private readonly buyerService: BuyerService) {}

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Get('me')
    @ApiDocsGetCurrentBuyerData()
    async getCurrentBuyerData(@Req() req: Request): Promise<BuyerResponseDto> {
        return this.buyerService.getCurrentBuyerData(req.tokenData!.email);
    }

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
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

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Put('me/card')
    @ApiDocsSaveOrReplaceCurrentBuyerCard()
    async saveOrReplaceCurrentBuyerCard(
        @Req() req: any,
        @Body() body: CreateCardDto,
    ) {
        return await this.buyerService.saveOrReplaceCurrentBuyerCard(
            req.tokenData!.sub,
            body,
        );
    }

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Delete('me/card')
    @ApiDocsDeleteCurrentBuyerCard()
    async deleteCurrentBuyerCard(@Req() req: Request) {
        return this.buyerService.deleteCurrentBuyerCard(req.tokenData!.sub);
    }

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Get('me/wishlist')
    @ApiDocsGetCurrentBuyerWishlist()
    async getWishlist(@Req() req: Request) {
        const userId = req.tokenData!.sub;
        return this.buyerService.getWishlist(userId);
    }

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
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
