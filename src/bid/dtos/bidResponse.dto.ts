import { ApiProperty } from '@nestjs/swagger';
import { BidExpectedResponseTime, BidStatus } from '@prisma/client';
import { BuyerResponseDto } from 'src/buyer/dtos/buyerResponse.dto';

export class BidResponseDto {
    @ApiProperty({
        description: 'Unique identifier of the bid',
        example: 'b6fa7c48-9c12-4a5f-a421-57dcf621d932',
    })
    bidId: string;

    @ApiProperty({
        description: 'Name of the bid',
        example: 'Construction Equipment Supply',
    })
    bidName: string;

    @ApiProperty({
        description: 'The main activity or subject of the bid',
        example: 'Supplying construction materials and heavy machinery',
    })
    mainActivity: string;

    @ApiProperty({
        description: 'Deadline for submitting offers for this bid',
        example: '2025-12-31T23:59:59Z',
        type: String,
        format: 'date-time',
    })
    submissionDeadline: Date;

    @ApiProperty({
        description: 'Expected response time from suppliers',
        enum: BidExpectedResponseTime,
        example: BidExpectedResponseTime.ONE_WEEK,
    })
    expectedResponseTime: BidExpectedResponseTime;

    @ApiProperty({
        description: 'Current status of the bid',
        enum: BidStatus,
        example: BidStatus.OPEN,
    })
    status: BidStatus;

    @ApiProperty({
        description: 'Information about the buyer who created this bid',
        type: () => BuyerResponseDto,
    })
    buyer: BuyerResponseDto;

    @ApiProperty({
        description: 'Date and time when this bid was created',
        example: '2025-10-17T10:00:00Z',
        type: String,
        format: 'date-time',
    })
    createdAt: Date;
}
