import { ApiPropertyOptional } from '@nestjs/swagger';
import {
    IsArray,
    IsEmail,
    IsOptional,
    IsString,
    MaxLength,
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

    @ApiPropertyOptional({
        example: ['Home & Living', 'Technical & Repair Services'],
        type: [String],
    })
    @IsArray()
    @IsOptional()
    @IsString({ each: true })
    categories?: string[];
}
