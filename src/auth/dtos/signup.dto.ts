import {
  ArrayMinSize,
  ArrayNotEmpty,
  IsArray,
  IsBoolean,
  IsEmail,
  IsNotEmpty,
  IsNumber,
  IsString,
  Matches,
  MaxLength,
  MinLength,
} from 'class-validator';

export class SignupDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(8, { message: 'Password must be at least 8 characters' })
  @MaxLength(28, { message: 'Password must not exceed 28 characters' })
  password: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(25)
  name: string;

  @IsString()
  @IsNotEmpty()
  @Matches(/^\d{10}$/, { message: 'CRN must be exactly 10 digits' })
  crn: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(50)
  businessName: string;

  @IsString()
  @IsNotEmpty()
  city: string;

  @IsString()
  @IsNotEmpty()
  @Matches(/^\d{10}$/, { message: 'NID must be exactly 10 digits' })
  nid: string;

  @IsArray()
  @ArrayNotEmpty()
  @ArrayMinSize(1)
  @IsString({ each: true })
  categories: string[];

  @IsBoolean()
  @IsNotEmpty()
  agreedToTerms: boolean;
}
