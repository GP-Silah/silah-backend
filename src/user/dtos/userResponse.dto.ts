import { ApiProperty } from '@nestjs/swagger';
import { UserRole } from '../../enums/userRole';

export class UserResponseDTO {
    @ApiProperty({ example: 'clv70z13w0000unqoj4lcr8x4' })
    id: string;

    @ApiProperty({ example: 'John Doe' })
    name: string;

    @ApiProperty({ example: 'user@example.com' })
    email: string;

    @ApiProperty({ example: '1234567890' })
    crn: string;

    @ApiProperty({ example: 'Acme Corp' })
    businessName: string;

    @ApiProperty({ enum: UserRole, example: UserRole.BUYER })
    role: UserRole;

    @ApiProperty({ example: 'Riyadh' })
    city: string;

    @ApiProperty({
        example: 'https://cdn.example.com/pfp/abc123.png', //TODO: Replace with actual example URL
        required: false,
    })
    pfpUrl?: string;

    @ApiProperty({
        example: ['Home & Living', 'Technical & Repair Services'],
        type: [String],
    })
    categories: string[];

    @ApiProperty({ example: true })
    isEmailVerified: boolean;

    @ApiProperty({ example: '2025-07-04T7:31:00.000Z' })
    createdAt: Date;

    @ApiProperty({ example: '2025-07-05T14:48:00.000Z' })
    updatedAt: Date;
}
