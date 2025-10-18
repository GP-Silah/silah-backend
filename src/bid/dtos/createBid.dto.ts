import { ApiProperty } from '@nestjs/swagger';
import { BidExpectedResponseTime } from '@prisma/client';
import {
    IsString,
    IsNotEmpty,
    IsDateString,
    IsEnum,
    MaxLength,
} from 'class-validator';
import { IsFutureDate } from 'src/invoice/dtos/createInvoice.dto';

export class CreateBidDto {
    @ApiProperty({
        description: 'Name of the bid',
        example: 'IT Hardware Supply',
        maxLength: 100,
    })
    @IsString()
    @IsNotEmpty()
    @MaxLength(100, { message: 'Bid name must not exceed 100 characters' })
    bidName: string;

    @ApiProperty({
        description: 'Main activity or purpose of the bid',
        example: 'Supplying laptops and accessories for company use',
        maxLength: 500,
    })
    @IsString()
    @IsNotEmpty()
    @MaxLength(500, { message: 'Main activity must not exceed 500 characters' })
    mainActivity: string;

    @ApiProperty({
        description:
            'Deadline for suppliers to submit offers (must be a future date)',
        example: '2025-11-30',
    })
    @IsDateString()
    @IsFutureDate({ message: 'Submission deadline must be in the future' })
    submissionDeadline: Date;

    @ApiProperty({
        description: 'Expected response time',
        enum: BidExpectedResponseTime,
        example: BidExpectedResponseTime.ONE_WEEK,
    })
    @IsEnum(BidExpectedResponseTime)
    expectedResponseTime: BidExpectedResponseTime;
}
