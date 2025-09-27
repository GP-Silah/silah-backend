import {
    IsOptional,
    IsString,
    MaxLength,
    IsNumber,
    IsPositive,
    IsInt,
    IsBoolean,
    IsArray,
    ArrayMinSize,
    ArrayMaxSize,
    IsEnum,
} from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';
import { ServiceAvailability } from '@prisma/client';

export class UpdateServiceDto {
    @ApiPropertyOptional({ description: 'Service name', maxLength: 60 })
    @IsOptional()
    @IsString()
    @MaxLength(60)
    name?: string;

    @ApiPropertyOptional({
        description: 'Service description',
        maxLength: 1000,
    })
    @IsOptional()
    @IsString()
    @MaxLength(1000)
    description?: string;

    @ApiPropertyOptional({ description: 'Service price', example: 150.0 })
    @IsOptional()
    @IsNumber()
    @IsPositive()
    price?: number;

    @ApiPropertyOptional({
        description: 'Indicates if the price is negotiable',
        example: true,
    })
    @IsOptional()
    @IsBoolean()
    isPriceNegotiable?: boolean;

    @ApiPropertyOptional({ description: 'Category ID', example: 1 })
    @IsOptional()
    @IsInt()
    categoryId?: number;

    @ApiPropertyOptional({
        description: 'Availability details of the service',
        example: 'EVERYDAY',
        enum: ServiceAvailability,
    })
    @IsOptional()
    @IsEnum(ServiceAvailability)
    serviceAvailability?: ServiceAvailability;

    @ApiPropertyOptional({ description: 'Publish status', example: false })
    @IsOptional()
    @IsBoolean()
    isPublished?: boolean;
}
