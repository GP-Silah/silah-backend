import { Controller, Delete, Get, Patch, Post } from '@nestjs/common';
import { CartService } from './cart.service';
import { ApiTags } from '@nestjs/swagger';

@ApiTags('Carts')
@Controller('carts')
export class CartController {
    constructor(private readonly cartService: CartService) {}

    @Get(':buyerId')
    async getBuyerActiveCart() {}

    // auto creation when first item is added
    @Post('/items')
    async addItem() {}

    @Patch(':cartId/items/:itemId')
    async updateItemQuantity() {}

    @Delete(':cartId/items/:itemId')
    async removeItem() {}

    @Delete(':cartId')
    async clearCart() {}

    @Delete(':cartId/suppliers/:supplierId')
    async removeSupplierFromCart() {}

    // internally creates multiple orders
    @Post(':cartId/checkout')
    async checkoutCart() {}
}
