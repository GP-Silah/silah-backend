import { GroupPurchaseStatus } from '@prisma/client';
import { BuyerResponseDto } from 'src/buyer/dtos/buyerResponse.dto';
import { ProductResponseDto } from 'src/product/dtos/productResponse.dto';
import { SupplierResponseDto } from 'src/supplier/dtos/supplierResponse.dto';
import { ApiProperty, getSchemaPath } from '@nestjs/swagger';
import { InactiveSupplierResponseDto } from 'src/supplier/dtos/inactiveSupplierResponse.dto';

export class GroupPurchaseBuyerResponseDto {
    @ApiProperty({ description: 'ID of the group purchase buyer' })
    groupPurchaseBuyerId: string;

    @ApiProperty({
        type: () => BuyerResponseDto,
        description: 'Buyer details',
    })
    buyer: BuyerResponseDto;

    @ApiProperty({ description: 'Quantity chosen by the buyer' })
    quantity: number;

    @ApiProperty({ description: 'Price based on chosen quantity' })
    priceBasedQuantity: number;

    @ApiProperty({ description: 'Date and time when the buyer joined' })
    joinedAt: Date;
}

export class GroupPurchaseResponseDto {
    @ApiProperty({ description: 'ID of the group purchase' })
    groupPurchaseId: string;

    @ApiProperty({ description: 'City of the buyers in this group purchase' })
    city: string;

    @ApiProperty({ description: 'Minimum group quantity set by the supplier' })
    minGroupQuantity: number;

    @ApiProperty({ description: 'Actual cumulative quantity joined so far' })
    actualGroupQuantity: number;

    @ApiProperty({ description: 'Remaining quantity to reach the minimum' })
    remainingQuantity: number;

    @ApiProperty({ description: 'Total price of the group purchase' })
    totalPrice: number;

    @ApiProperty({
        description: 'Discounted price per unit for the group purchase',
    })
    groupUnitPrice: number;

    @ApiProperty({
        description: 'Discount percentage compared to product regular price',
    })
    discountPercentage: number;

    @ApiProperty({ description: 'Deadline for the group purchase' })
    deadline: Date;

    @ApiProperty({
        enum: GroupPurchaseStatus,
        description: 'Status of the group purchase',
    })
    status: GroupPurchaseStatus;

    @ApiProperty({ type: () => ProductResponseDto })
    product: ProductResponseDto;

    @ApiProperty({
        oneOf: [
            { $ref: getSchemaPath(SupplierResponseDto) },
            { $ref: getSchemaPath(InactiveSupplierResponseDto) },
        ],
        description: 'Supplier details (active or inactive)',
    })
    supplier: SupplierResponseDto | InactiveSupplierResponseDto;

    @ApiProperty({
        type: () => [GroupPurchaseBuyerResponseDto],
        description: 'List of buyers who joined this group purchase',
    })
    joinedBuyers: GroupPurchaseBuyerResponseDto[];

    @ApiProperty({
        description: 'Date and time when the group purchase was created',
    })
    createdAt: Date;
}
