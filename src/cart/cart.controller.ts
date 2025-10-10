import {
    Controller,
    Delete,
    Get,
    Patch,
    Post,
    Req,
    UseGuards,
    Body,
    Param,
    BadRequestException,
    ParseIntPipe,
} from '@nestjs/common';
import { CartService } from './cart.service';
import { ApiTags } from '@nestjs/swagger';
import { ApiDocsJwtAuthGuard } from 'src/auth/decorators/jwt-auth-guard.docs';
import { ApiDocsRolesGuard } from 'src/auth/decorators/roles-guard.docs';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { UserRole } from 'src/enums/userRole.enum';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { Request } from 'express';
import { AddCartItemDto } from './dtos/addCartItem.dto';
import {
    ApiDocsAddCartItem,
    ApiDocsCheckoutCart,
    ApiDocsDeleteCart,
    ApiDocsGetBuyerActiveCart,
    ApiDocsRemoveItem,
    ApiDocsRemoveSupplierFromCart,
    ApiDocsUpdateItemQuantity,
} from './cart.docs';
import { CheckoutCartDto } from './dtos/checkoutCart.dto';
import { ApiDocsVerifiedGuard } from 'src/auth/decorators/verified-guard.docs';
import { VerifiedGuard } from 'src/auth/guards/verified.guard';

@ApiTags('Carts')
@Controller('carts')
export class CartController {
    constructor(private readonly cartService: CartService) {}

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Get('me')
    @ApiDocsGetBuyerActiveCart()
    async getBuyerActiveCart(@Req() req: Request) {
        const userId = req.tokenData!.sub;
        return this.cartService.getBuyerActiveCart(userId);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    // auto creation when first item is added
    @Post('me/items')
    @ApiDocsAddCartItem()
    async addItem(@Req() req: Request, @Body() dto: AddCartItemDto) {
        const userId = req.tokenData!.sub;
        return this.cartService.addItem(userId, dto);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Patch('me/items/:itemId')
    @ApiDocsUpdateItemQuantity()
    async updateItemQuantity(
        @Req() req: Request,
        @Param('itemId', ParseIntPipe) itemId: number,
        @Body('newQuantity') newQuantity: number,
    ) {
        console.log(typeof newQuantity, newQuantity);
        if (!newQuantity || newQuantity < 1) {
            throw new BadRequestException(
                'New quantity cannot be null or less than 1',
            );
        }
        const userId = req.tokenData!.sub;
        return this.cartService.updateItemQuantity(userId, itemId, newQuantity);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Delete('me/items/:itemId')
    @ApiDocsRemoveItem()
    async removeItem(@Req() req: Request, @Param('itemId') itemId: number) {
        const userId = req.tokenData!.sub;
        return this.cartService.removeItem(userId, itemId);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Delete('me')
    @ApiDocsDeleteCart()
    async deleteCart(@Req() req: Request) {
        const userId = req.tokenData!.sub;
        return this.cartService.deleteCart(userId);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Delete('me/suppliers/:supplierId')
    @ApiDocsRemoveSupplierFromCart()
    async removeSupplierFromCart(
        @Req() req: Request,
        @Param('supplierId') supplierId: string,
    ) {
        const userId = req.tokenData!.sub;
        return this.cartService.removeSupplierFromCart(userId, supplierId);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @Post('me/checkout')
    @ApiDocsCheckoutCart()
    async checkoutCart(@Req() req: Request, @Body() dto: CheckoutCartDto) {
        const userId = req.tokenData!.sub;
        return this.cartService.checkoutCart(userId, dto);
    }
}
