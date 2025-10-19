import { ApiProperty, getSchemaPath } from '@nestjs/swagger';
import { OfferStatus } from '@prisma/client';
import { BidResponseDto } from 'src/bid/dtos/bidResponse.dto';
import { InactiveSupplierResponseDto } from 'src/supplier/dtos/inactiveSupplierResponse.dto';
import { SupplierResponseDto } from 'src/supplier/dtos/supplierResponse.dto';

export class OfferResponseDto {
    @ApiProperty({
        example: '123e4567-e89b-12d3-a456-426614174000',
        description: 'Unique identifier for the offer.',
    })
    offerId: string;

    @ApiProperty({
        example: 5000,
        description:
            'The proposed amount by the supplier for completing the bid.',
    })
    proposedAmount: number;

    @ApiProperty({
        example: '2025-12-01',
        description: 'Expected completion time proposed by the supplier.',
        type: String,
        format: 'date',
    })
    expectedCompletionTime: Date;

    @ApiProperty({
        example: 'We can deliver the requested items within two weeks.',
        description: 'Details of the offer provided by the supplier.',
        maxLength: 500,
    })
    offerDetails: string;

    @ApiProperty({
        example:
            'Execution will be carried out in two phases: procurement and delivery.',
        description:
            'Explanation of how the supplier plans to execute the offer.',
        maxLength: 500,
    })
    executionDetails: string;

    @ApiProperty({
        example:
            'Please note, prices may vary slightly with market fluctuations.',
        description: 'Optional notes or remarks from the supplier.',
        required: false,
        maxLength: 500,
    })
    notes?: string;

    @ApiProperty({
        example: OfferStatus.PENDING,
        enum: OfferStatus,
        description: 'Current status of the offer.',
    })
    status: OfferStatus;

    @ApiProperty({
        oneOf: [
            { $ref: getSchemaPath(SupplierResponseDto) },
            { $ref: getSchemaPath(InactiveSupplierResponseDto) },
        ],
        description: 'Supplier who made the offer.',
    })
    supplier: SupplierResponseDto | InactiveSupplierResponseDto;

    @ApiProperty({
        type: () => BidResponseDto,
        description: 'Bid associated with this offer.',
    })
    bid: BidResponseDto;

    @ApiProperty({
        example: '2025-10-10T14:48:00Z',
        description: 'Timestamp when the offer was created.',
        type: String,
        format: 'date-time',
    })
    createdAt: Date;
}
