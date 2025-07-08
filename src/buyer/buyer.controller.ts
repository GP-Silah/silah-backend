import { Controller, Delete, Get, Post } from '@nestjs/common';
import { BuyerService } from './buyer.service';
import { ApiTags } from '@nestjs/swagger';
import { BuyerResponseDto } from './dtos/buyerResponse.dto';

@ApiTags('Buyers')
@Controller('buyers')
export class BuyerController {
    constructor(private readonly buyerService: BuyerService) {}

    @Get('me')
    async getCurrentBuyerData(): Promise<BuyerResponseDto> {}

    //TODO: Come back to these after the WishlistItemDto is finalized
    @Get('wishlist')
    async getWishlist() {}

    @Post('wishlist/:itemId')
    async addToWishlist() {}

    @Delete('wishlist/:itemId')
    async removeFromWishlist() {}
}
