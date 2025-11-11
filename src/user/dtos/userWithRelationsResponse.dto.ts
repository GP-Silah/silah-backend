import { ApiProperty } from '@nestjs/swagger';
import { UserResponseDTO } from './userResponse.dto';
import { BuyerResponseDto } from 'src/buyer/dtos/buyerResponse.dto';
import { SupplierResponseDto } from 'src/supplier/dtos/supplierResponse.dto';
import { InactiveSupplierResponseDto } from 'src/supplier/dtos/inactiveSupplierResponse.dto';

export class UserWithRelationsResponseDTO {
    @ApiProperty({ type: () => UserResponseDTO })
    user: UserResponseDTO;

    @ApiProperty({ type: () => BuyerResponseDto, nullable: true })
    buyer?: BuyerResponseDto | null;

    @ApiProperty({
        oneOf: [
            { $ref: '#/components/schemas/SupplierResponseDto' },
            { $ref: '#/components/schemas/InactiveSupplierResponseDto' },
        ],
        nullable: true,
    })
    supplier?: SupplierResponseDto | InactiveSupplierResponseDto | null;
}
