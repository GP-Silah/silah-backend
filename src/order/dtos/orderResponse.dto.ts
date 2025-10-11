import { ApiProperty, getSchemaPath } from '@nestjs/swagger';
import { OrderStatus } from '@prisma/client';
import { BuyerResponseDto } from 'src/buyer/dtos/buyerResponse.dto';
import { SupplierResponseDto } from 'src/supplier/dtos/supplierResponse.dto';
import { ProductResponseDto } from 'src/product/dtos/productResponse.dto';
import { InactiveSupplierResponseDto } from 'src/supplier/dtos/inactiveSupplierResponse.dto';

export class OrderItemResponseDto {
    @ApiProperty({
        description: 'Unique identifier of this order item record.',
        example: 101,
    })
    orderItemId: number;

    @ApiProperty({
        description:
            'The unique identifier of the parent order this item belongs to.',
        example: '23bd9a1c-51b2-44d5-99cc-71b15a4d9d31',
    })
    orderId: string;

    @ApiProperty({
        description:
            'Snapshot of the product associated with this item at the time of checkout.',
        type: ProductResponseDto,
    })
    product?: ProductResponseDto;

    @ApiProperty({
        description: 'Number of units purchased for this specific product.',
        example: 2,
    })
    quantity: number;

    @ApiProperty({
        description: 'Price per unit at the time of purchase (in SAR).',
        example: 59.99,
    })
    unitPrice: number;

    @ApiProperty({
        description:
            'Total price for this line item, computed as `quantity * unitPrice`.',
        example: 119.98,
    })
    totalPrice: number;

    @ApiProperty({
        description:
            'Timestamp when this order item record was created in the database.',
        example: '2025-10-11T12:45:00.000Z',
    })
    createdAt: Date;
}

export class OrderResponseDto {
    @ApiProperty({ description: 'Unique identifier of the order.' })
    orderId: string;

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
            'The list of items included in this order, with their product details and purchase information.',
        type: [OrderItemResponseDto],
    })
    items: OrderItemResponseDto[];

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
}
