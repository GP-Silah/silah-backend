import { ApiProperty } from '@nestjs/swagger';

export class CartItemResponseDto {
    @ApiProperty({ description: 'Cart item ID', example: 1 })
    cartItemId: number;

    @ApiProperty({
        description: 'Product ID',
        example: 'a1b2c3d4-5678-90ab-cdef-1234567890ab',
    })
    productId: string;

    @ApiProperty({
        description: 'Product name',
        example: 'Hair brushes',
    })
    productName: string;

    @ApiProperty({
        description: 'Product price',
        example: 25.0,
    })
    productPrice: number;

    @ApiProperty({ description: 'Quantity of the product', example: 2 })
    quantity: number;

    @ApiProperty({
        description: 'Total price for this item (price * quantity)',
        example: 50.5,
    })
    itemTotalPrice: number;

    @ApiProperty({
        description:
            'Whether the product is currently available (stock >= quantity)',
        example: true,
    })
    isAvailable: boolean;
}

export class CartBySupplierResponseDto {
    @ApiProperty({
        description: 'CartBySupplier ID',
        example: 'f1e2d3c4-5678-90ab-cdef-1234567890ab',
    })
    cartBySupplierId: string;

    @ApiProperty({
        description: 'Supplier ID',
        example: 'z1x2c3v4-5678-90ab-cdef-1234567890ab',
    })
    supplierId: string;

    @ApiProperty({ description: 'Delivery fee of this supplier', example: 5.0 })
    deliveryFee: number;

    @ApiProperty({
        description:
            "Subtotal for this supplier's items (without delivery fee)",
        example: 45.5,
    })
    subTotal: number;

    @ApiProperty({
        description: 'Total price including delivery fee',
        example: 50.5,
    })
    supplierTotalPrice: number;

    @ApiProperty({
        type: [CartItemResponseDto],
        description: 'Items from this supplier',
    })
    cartItems: CartItemResponseDto[];
}

export class CartResponseDto {
    @ApiProperty({
        description: 'Cart ID',
        example: 'b1c2d3e4-5678-90ab-cdef-1234567890ab',
    })
    cartId: string;

    @ApiProperty({
        description: 'Buyer ID',
        example: 'y1x2w3v4-5678-90ab-cdef-1234567890ab',
    })
    buyerId: string;

    @ApiProperty({
        description: 'Total of all product prices in the cart',
        example: 100.0,
    })
    productsTotal: number;

    @ApiProperty({
        description: 'Total delivery fees from all suppliers',
        example: 10.0,
    })
    deliveryFees: number;

    @ApiProperty({
        description: 'Total cart price (productsTotal + deliveryFees)',
        example: 110.0,
    })
    cartTotal: number;

    @ApiProperty({
        description: 'Whether the cart has been checked out',
        example: false,
    })
    isBought: boolean;

    @ApiProperty({
        type: [CartBySupplierResponseDto],
        description: 'List of suppliers with their items',
    })
    suppliers: CartBySupplierResponseDto[];
}
