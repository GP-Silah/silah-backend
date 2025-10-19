import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
    IsDateString,
    IsUUID,
    MaxLength,
    IsOptional,
    IsNumber,
    Min,
    IsString,
} from 'class-validator';
import { IsFutureDate } from 'src/invoice/dtos/createInvoice.dto';

export class CreateOfferDto {
    @ApiProperty({
        description: 'Proposed amount for the bid.',
        example: 25000,
        minimum: 1,
    })
    @IsNumber({ maxDecimalPlaces: 2 })
    @Min(1, { message: 'Proposed amount must be greater than 0' })
    proposedAmount: number;

    @ApiProperty({
        description: 'Expected completion time (must be a future date).',
        example: '2025-12-01',
        type: String,
        format: 'date',
    })
    @IsDateString()
    @IsFutureDate({ message: 'Expected completion time must be in the future' })
    expectedCompletionTime: Date;

    @ApiProperty({
        description: 'Details of the offer.',
        example:
            'We will complete the project within 2 weeks using our experienced team.',
        maxLength: 500,
    })
    @IsString()
    @MaxLength(500, { message: 'Offer details must not exceed 500 characters' })
    offerDetails: string;

    @ApiProperty({
        description:
            'Execution details explaining how the supplier will perform the work.',
        example:
            'Execution includes planning, sourcing materials, and on-site installation.',
        maxLength: 500,
    })
    @IsString()
    @MaxLength(500, {
        message: 'Execution details must not exceed 500 characters',
    })
    executionDetails: string;

    @ApiPropertyOptional({
        description: 'Optional notes or remarks.',
        example: 'Delivery may vary depending on customs clearance.',
        maxLength: 500,
    })
    @IsOptional()
    @IsString()
    @MaxLength(500, { message: 'Notes must not exceed 500 characters' })
    notes?: string;
}
