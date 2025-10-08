import { ApiProperty, getSchemaPath } from '@nestjs/swagger';
import { Buyer, OrderStatus } from '@prisma/client';
import { CartItemResponseDto } from '../../cart/dtos/cartResponse.dto';
import { BuyerResponseDto } from 'src/buyer/dtos/buyerResponse.dto';
import { SupplierResponseDto } from 'src/supplier/dtos/supplierResponse.dto';
import { ProductResponseDto } from 'src/product/dtos/productResponse.dto';
import { InactiveSupplierResponseDto } from 'src/supplier/dtos/inactiveSupplierResponse.dto';

export class OrderResponseDto {
    @ApiProperty({ description: 'Unique identifier of the order.' })
    id: string;

    @ApiProperty({
        description: `Unique identifier for the Tap Payments charge session.<br><br>
            When a buyer proceeds to checkout, all items in their cart that belong to the same supplier 
            are grouped into a single order. However, multiple orders (one per supplier) can still 
            originate from the same checkout session.<br><br>
            The <code>tapChargeId</code> serves as a shared reference linking all orders 
            created during that checkout flow, allowing the system to trace which orders 
            were generated from the same payment attempt.`,
        example: 'chg_x8q3x9l7z5w2y1v0',
    })
    tapChargeId: string;

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

    @ApiProperty({
        description: 'Buyer info for this order',
        type: BuyerResponseDto,
    })
    buyer: BuyerResponseDto | null;

    @ApiProperty({
        description: 'Supplier info for this order',
        oneOf: [
            { $ref: getSchemaPath(SupplierResponseDto) },
            { $ref: getSchemaPath(InactiveSupplierResponseDto) },
        ],
    })
    supplier: SupplierResponseDto | InactiveSupplierResponseDto | null;

    @ApiProperty({
        description: 'List of products in this order',
        type: [ProductResponseDto],
    })
    products: ProductResponseDto[];
}
