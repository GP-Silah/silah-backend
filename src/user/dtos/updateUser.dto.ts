import { ApiPropertyOptional } from '@nestjs/swagger';
import { Languages } from '@prisma/client';
import { Type } from 'class-transformer';
import {
    IsArray,
    IsEmail,
    IsEnum,
    IsInt,
    IsOptional,
    IsString,
    MaxLength,
    Min,
    MinLength,
} from 'class-validator';

export class UpdateUserDto {
    @ApiPropertyOptional({ example: 'John Doe', maxLength: 25 })
    @IsString()
    @IsOptional()
    @MaxLength(25)
    name?: string;

    @ApiPropertyOptional({ example: 'user@example.com' })
    @IsEmail()
    @IsOptional()
    email?: string;

    @ApiPropertyOptional({
        example: 'StrongPass123',
        minLength: 8,
        maxLength: 28,
    })
    @IsString()
    @IsOptional()
    @MinLength(8, { message: 'Password must be at least 8 characters' })
    @MaxLength(28, { message: 'Password must not exceed 28 characters' })
    newPassword?: string;

    @ApiPropertyOptional({ example: 'Acme Corp', maxLength: 50 })
    @IsString()
    @IsOptional()
    @MaxLength(50)
    businessName?: string;

    @ApiPropertyOptional({ example: 'Riyadh' })
    @IsString()
    @IsOptional()
    city?: string;

    @ApiPropertyOptional({ example: 'ARA', enum: Languages })
    @IsOptional()
    @IsEnum(Languages)
    preferredLanguage?: Languages;

    @ApiPropertyOptional({
        description: 'List of category IDs (use IDs, not names).',
        type: Number,
        isArray: true,
        example: [5, 14],
    })
    @IsOptional()
    @IsArray()
    @Type(() => Number) // transforms "['5','14']" => [5,14] when ValidationPipe.transform = true
    @IsInt({ each: true }) // ensure each item is an integer
    @Min(1, { each: true }) // ensure positive IDs
    categories?: number[];
}
