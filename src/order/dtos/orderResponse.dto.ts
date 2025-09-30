import { ApiProperty } from '@nestjs/swagger';
import { OrderStatus } from '@prisma/client';
import { CartItemResponseDto } from '../../cart/dtos/cartResponse.dto';

export class OrderResponseDto {
    @ApiProperty({ description: 'Unique identifier of the order.' })
    id: string;

    @ApiProperty({
        description: `Identifier for the checkout session.<br>
        Since a buyer can have items from multiple suppliers in a single cart, 
        each supplier will generate a separate order, but all share the same checkoutId.`,
    })
    checkoutId: string;

    @ApiProperty({
        description:
            'The ID of the buyer who placed this order. Nullable if the buyer account is deleted or unavailable.',
    })
    buyerId?: string;

    @ApiProperty({
        description:
            'The ID of the cart from which this order was created. Useful for tracing back to the original cart items and totals.',
    })
    cartId: string;

    @ApiProperty({
        description:
            'The ID of the supplier fulfilling this order. Each order is tied to a single supplier even if multiple suppliers were in the cart.',
    })
    supplierId: string;

    @ApiProperty({
        description:
            'The final price of this order. This includes the total cost of the items from the supplier plus any delivery fees.',
    })
    finalPrice: number;

    @ApiProperty({
        description:
            'Current status of the order. Values can be PENDING, PROCESSING, SHIPPED, or COMPLETED.',
        enum: OrderStatus,
    })
    status: OrderStatus;

    @ApiProperty({
        description:
            'Timestamp when the order was created. Useful for order history, tracking, and reporting.',
    })
    createdAt: Date;

    @ApiProperty({
        description:
            'The items included in this order, with their details such as product info, quantity, and total price for each item.',
        type: [CartItemResponseDto],
    })
    items: CartItemResponseDto[];
}
