import { SupplierStatus } from '@prisma/client';
import { ApiProperty } from '@nestjs/swagger';

export class InactiveSupplierResponseDto {
    @ApiProperty({ description: 'Supplier unique ID', example: 'uuid-1234' })
    supplierId: string;

    @ApiProperty({ description: 'Supplier display name', example: 'John Doe' })
    supplierName: string;

    @ApiProperty({
        description: 'Business name of the user',
        example: 'John Bakery',
    })
    businessName: string;

    @ApiProperty({ description: 'City of the user', example: 'Riyadh' })
    city: string;

    @ApiProperty({
        enum: SupplierStatus,
        description: 'Current status of the supplier account',
        example: SupplierStatus.INACTIVE,
    })
    supplierStatus: SupplierStatus;

    @ApiProperty({
        description:
            'Message explaining why supplier information is limited (inactive account).',
        example:
            'This supplier is inactive and cannot be accessed until they renew their subscription.',
    })
    message: string;
}
