import { ApiProperty } from '@nestjs/swagger';
import {
    IsNotEmpty,
    IsString,
    Matches,
    MaxLength,
    MinLength,
} from 'class-validator';

export class ResetPasswordDto {
    @ApiProperty({
        description:
            'The new password to replace the old one.<br>Password must contain at least one uppercase, one lowercase, and one number. Special characters (@, #, !, $) are optional.',
        example: 'StrongPass123',
        minLength: 8,
        maxLength: 28,
    })
    @IsString()
    @IsNotEmpty()
    @MinLength(8, { message: 'Password must be at least 8 characters' })
    @MaxLength(28, { message: 'Password must not exceed 28 characters' })
    @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d@#!$]+$/, {
        message:
            'Password must contain at least one uppercase, one lowercase, and one number. Only @, #, !, $ special characters are allowed.',
    })
    newPassword: string;
}
