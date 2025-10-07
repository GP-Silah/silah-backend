import { ApiProperty } from '@nestjs/swagger';
import { UserRole } from '../../enums/userRole.enum';
import { Languages } from '@prisma/client';

export class UserResponseDTO {
    @ApiProperty({ example: 'clv70z13w0000unqoj4lcr8x4' })
    userId: string;

    @ApiProperty({ example: 'cus_13gdft5' })
    tapCustomerId: string;

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
        example: 'moon-3263ec71-3e92-441d-aadd-a57b4a99b2e2.jpeg',
        description: 'Profile picture file name in R2 bucket.',
    })
    pfpFileName: string;

    @ApiProperty({
        example:
            'https://gp-silah.d025be9440ae5eb8295c69a36497276a.r2.cloudflarestorage.com/gp-silah/moon.jpeg-30510246-41f7-4cff-a052-78bcc30f7301.jpeg?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=...&X-Amz-Date=20250816T131236Z&X-Amz-Expires=3600&X-Amz-Signature=...',
        description:
            'Signed URL from R2. Signed URLs expire 1 hour after creation.',
        format: 'uri',
    })
    pfpUrl: string;

    @ApiProperty({
        type: [Object],
        example: [
            { id: 5, name: 'Home & Living' },
            { id: 14, name: 'Technical & Repair Services' },
        ],
    })
    categories: { id: number; name: string }[];

    @ApiProperty({ example: true })
    isEmailVerified: boolean;

    @ApiProperty({ example: 'ARA', enum: Languages })
    preferredLanguage: Languages;

    @ApiProperty({ example: '2025-07-04T7:31:00.000Z' })
    createdAt: Date;

    @ApiProperty({ example: '2025-07-05T14:48:00.000Z' })
    updatedAt: Date;
}
