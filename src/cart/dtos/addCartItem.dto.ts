import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsUUID, IsInt, Min } from 'class-validator';

export class AddCartItemDto {
    @ApiProperty({
        description: 'ID of the product to add to the cart',
        example: 'a1b2c3d4-5678-90ab-cdef-1234567890ab',
    })
    @IsString()
    @IsUUID()
    productId: string;

    @ApiProperty({
        description: 'Quantity of the product to add (minimum 1)',
        example: 2,
        minimum: 1,
    })
    @IsInt()
    @Min(1)
    quantity: number;
}
