import {
    ArrayMinSize,
    ArrayNotEmpty,
    Equals,
    IsArray,
    IsBoolean,
    IsEmail,
    IsNotEmpty,
    IsString,
    Matches,
    MaxLength,
    MinLength,
    IsInt,
    Min,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { Type } from 'class-transformer';

export class SignupDto {
    @ApiProperty({ example: 'user@example.com' })
    @IsEmail()
    @IsNotEmpty()
    email: string;

    @ApiProperty({
        example: 'StrongPass123',
        minLength: 8,
        maxLength: 28,
        description:
            'Password must contain at least one uppercase, one lowercase, and one number. Special characters (@, #, !, $) are optional.',
    })
    @IsString()
    @IsNotEmpty()
    @MinLength(8, { message: 'Password must be at least 8 characters' })
    @MaxLength(28, { message: 'Password must not exceed 28 characters' })
    @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d@#!$]+$/, {
        message:
            'Password must contain at least one uppercase, one lowercase, and one number. Only @, #, !, $ special characters are allowed.',
    })
    password: string;

    @ApiProperty({ example: 'John Doe' })
    @IsString()
    @IsNotEmpty()
    @MaxLength(25)
    name: string;

    @ApiProperty({ example: '1234567890' })
    @IsString()
    @IsNotEmpty()
    @Matches(/^\d{10}$/, {
        message: 'CRN must be exactly 10 digits (Numbers only)',
    })
    crn: string;

    @ApiProperty({ example: 'Acme Corp' })
    @IsString()
    @IsNotEmpty()
    @MaxLength(50)
    businessName: string;

    @ApiProperty({ example: 'Riyadh' })
    @IsString()
    @IsNotEmpty()
    city: string;

    @ApiProperty({ example: '0987654321' })
    @IsString()
    @IsNotEmpty()
    @Matches(/^\d{10}$/, {
        message: 'NID must be exactly 10 digits (Numbers only)',
    })
    nid: string;

    @ApiProperty({
        description: 'List of main category IDs (must be a main category).',
        type: Number,
        isArray: true,
        example: [1, 3],
    })
    @IsArray()
    @ArrayNotEmpty()
    @ArrayMinSize(1)
    @Type(() => Number)
    @IsInt({ each: true })
    @Min(1, { each: true })
    categories: number[];

    @ApiProperty({ example: true })
    @IsBoolean()
    @Equals(true, { message: 'You must agree to the terms and conditions' })
    @IsNotEmpty()
    agreedToTerms: boolean;
}
