import {
    Controller,
    Delete,
    Get,
    Patch,
    Post,
    Query,
    Req,
    UseGuards,
    Headers,
    Body,
    Param,
    BadRequestException,
    ParseIntPipe,
} from '@nestjs/common';
import { CartService } from './cart.service';
import { ApiTags } from '@nestjs/swagger';
import { ApiJwtAuthGuard } from 'src/auth/decorators/api-jwt-auth-guard.docs';
import { ApiRolesGuard } from 'src/auth/decorators/api-roles-guard.docs';
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

@ApiTags('Carts')
@Controller('carts')
export class CartController {
    constructor(private readonly cartService: CartService) {}

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Get()
    @ApiDocsGetBuyerActiveCart()
    async getBuyerActiveCart(
        @Req() req: Request,
        @Headers('accept-language') langHeader?: 'ar' | 'en',
        @Query('lang') lang?: 'ar' | 'en',
    ) {
        const finalLang = lang || langHeader || 'en';
        const userId = req.tokenData!.sub;
        return this.cartService.getBuyerActiveCart(userId, finalLang);
    }

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    // auto creation when first item is added
    @Post('/items')
    @ApiDocsAddCartItem()
    async addItem(@Req() req: Request, @Body() dto: AddCartItemDto) {
        const userId = req.tokenData!.sub;
        return this.cartService.addItem(userId, dto);
    }

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Patch(':cartId/items/:itemId')
    @ApiDocsUpdateItemQuantity()
    async updateItemQuantity(
        @Req() req: Request,
        @Param('cartId') cartId: string,
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
        return this.cartService.updateItemQuantity(
            userId,
            cartId,
            itemId,
            newQuantity,
        );
    }

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Delete(':cartId/items/:itemId')
    @ApiDocsRemoveItem()
    async removeItem(
        @Req() req: Request,
        @Param('cartId') cartId: string,
        @Param('itemId') itemId: number,
    ) {
        const userId = req.tokenData!.sub;
        return this.cartService.removeItem(userId, cartId, itemId);
    }

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Delete(':cartId')
    @ApiDocsDeleteCart()
    async deleteCart(@Req() req: Request, @Param('cartId') cartId: string) {
        const userId = req.tokenData!.sub;
        return this.cartService.deleteCart(userId, cartId);
    }

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Delete(':cartId/suppliers/:supplierId')
    @ApiDocsRemoveSupplierFromCart()
    async removeSupplierFromCart(
        @Req() req: Request,
        @Param('cartId') cartId: string,
        @Param('supplierId') supplierId: string,
    ) {
        const userId = req.tokenData!.sub;
        return this.cartService.removeSupplierFromCart(
            userId,
            cartId,
            supplierId,
        );
    }

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Post(':cartId/checkout')
    @ApiDocsCheckoutCart()
    async checkoutCart(@Req() req: Request, @Param('cartId') cartId: string) {
        const userId = req.tokenData!.sub;
        return this.cartService.checkoutCart(userId, cartId);
    }
}
