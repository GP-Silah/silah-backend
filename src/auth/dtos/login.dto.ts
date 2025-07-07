import {
    IsEmail,
    IsNotEmpty,
    IsOptional,
    IsString,
    Matches,
    MaxLength,
    MinLength,
    Validate,
} from 'class-validator';
import { IsEmailOrCrnConstraint } from './isEmailOrCrnConstraint';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class LoginDto {
    @ApiPropertyOptional({
        description: 'User email address (optional if CRN is provided)',
        example: 'user@example.com',
        format: 'email',
    })
    @IsOptional()
    @IsEmail()
    email?: string;

    @ApiPropertyOptional({
        description:
            'User CRN number (10 digits, optional if email is provided)',
        example: '1234567890',
        pattern: '^\\d{10}$',
    })
    @IsOptional()
    @Matches(/^\d{10}$/, {
        message: 'CRN must be exactly 10 digits (Numbers only)',
    })
    crn?: string;

    @ApiProperty({
        description: 'User password (8 to 28 characters)',
        example: 'P@ssw0rd123',
        minLength: 8,
        maxLength: 28,
    })
    @IsString()
    @IsNotEmpty()
    @MinLength(8, { message: 'Password must be at least 8 characters' })
    @MaxLength(28, { message: 'Password must not exceed 28 characters' })
    password: string;

    // Dummy field just to attach the validator, it's just a trick to apply class-level validation correctly with class-validator
    @ApiProperty({
        description:
            'Internal field to validate that either email or CRN is provided',
        example: true,
        readOnly: true,
    })
    @Validate(IsEmailOrCrnConstraint)
    readonly emailOrCrnCheck: boolean;
}
