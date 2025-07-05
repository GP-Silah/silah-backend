import { ApiProperty } from '@nestjs/swagger';
import {
  IsArray,
  IsEmail,
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';

export class UpdateUserDto {
  @ApiProperty({ example: 'John Doe', maxLength: 25 })
  @IsString()
  @IsOptional()
  @MaxLength(25)
  name?: string;

  @ApiProperty({ example: 'user@example.com' })
  @IsEmail()
  @IsOptional()
  email?: string;

  @ApiProperty({
    example: 'StrongPass123',
    minLength: 8,
    maxLength: 28,
  })
  @IsString()
  @IsOptional()
  @MinLength(8, { message: 'Password must be at least 8 characters' })
  @MaxLength(28, { message: 'Password must not exceed 28 characters' })
  newPassword?: string;

  @ApiProperty({ example: 'Acme Corp', maxLength: 50 })
  @IsString()
  @IsOptional()
  @MaxLength(50)
  businessName?: string;

  @ApiProperty({ example: 'Riyadh' })
  @IsString()
  @IsOptional()
  city?: string;

  @ApiProperty({
    example: ['Home & Living', 'Technical & Repair Services'],
    type: [String],
  })
  @IsArray()
  @IsOptional()
  @IsString({ each: true })
  categories?: string[];
}
