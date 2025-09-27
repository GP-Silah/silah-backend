import {
    IsString,
    IsNotEmpty,
    IsOptional,
    IsNumber,
    IsPositive,
    IsInt,
    MaxLength,
    IsBoolean,
    IsArray,
    ArrayMinSize,
    ArrayMaxSize,
    IsEnum,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { ServiceAvailability } from '@prisma/client';

export class CreateServiceDto {
    @ApiProperty({
        description: 'Service name',
        example: 'Home Cleaning',
        maxLength: 60,
    })
    @IsString()
    @IsNotEmpty()
    @MaxLength(60)
    name: string;

    @ApiProperty({
        description: 'Service description',
        example: 'Professional deep cleaning service for apartments and houses',
        maxLength: 1000,
    })
    @IsString()
    @IsNotEmpty()
    @MaxLength(1000)
    description: string;

    @ApiProperty({ description: 'Service price', example: 150.0 })
    @IsNumber()
    @IsPositive()
    price: number;

    @ApiPropertyOptional({
        description: 'Indicates if the price is negotiable (default = false)',
        example: true,
    })
    @IsOptional()
    @IsBoolean()
    isPriceNegotiable?: boolean;

    @ApiProperty({ description: 'Category ID', example: 1 })
    @IsInt()
    categoryId: number;

    @ApiProperty({
        description: 'Availability details of the service',
        example: 'TWENTY_FOUR_SEVEN',
        enum: ServiceAvailability,
    })
    @IsEnum(ServiceAvailability)
    serviceAvailability: ServiceAvailability;

    @ApiPropertyOptional({ description: 'Publish status (default = false)' })
    @IsOptional()
    @IsBoolean()
    isPublished?: boolean;
}
