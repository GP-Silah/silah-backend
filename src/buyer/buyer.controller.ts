import {
    Controller,
    Delete,
    Get,
    Post,
    Put,
    Req,
    UseGuards,
} from '@nestjs/common';
import { BuyerService } from './buyer.service';
import { ApiTags } from '@nestjs/swagger';
import { BuyerResponseDto } from './dtos/buyerResponse.dto';
import { CardDetailsDto } from './dtos/cardDetails.dto';
import { ApiJwtAuthGuard } from 'src/auth/decorators/api-jwt-auth-guard.docs';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { UserRole } from 'src/enums/userRole.enum';
import { Request } from 'express';

@ApiTags('Buyers')
@Controller('buyers')
export class BuyerController {
    constructor(private readonly buyerService: BuyerService) {}

    @ApiJwtAuthGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Get('me')
    async getCurrentBuyerData(@Req() req: Request): Promise<BuyerResponseDto> {
        return this.buyerService.getCurrentBuyerData(req.tokenData!.email);
    }

    @ApiJwtAuthGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Get('me/card')
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
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Put('me/card')
    async saveOrReplaceCurrentBuyerCard() {}

    @ApiJwtAuthGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Delete('me/card')
    async deleteCurrentBuyerCard() {}

    // TODO: Come back to these after the WishlistItemDto is finalized
    @Get('wishlist')
    async getWishlist() {}

    @Post('wishlist/:itemId')
    async addToWishlist() {}

    @Delete('wishlist/:itemId')
    async removeFromWishlist() {}
}
