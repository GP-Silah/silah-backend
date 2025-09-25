import { Controller, Delete, Get, Patch, Post } from '@nestjs/common';
import { ProductService } from './product.service';
import { ApiTags } from '@nestjs/swagger';

@ApiTags('Products')
@Controller('products')
export class ProductController {
    constructor(private readonly productService: ProductService) {}

    @Get()
    async getAllProducts() {}

    @Get(':productId')
    async getProductById() {}

    @Get('supplier/:supplierId')
    async getProductsBySupplier() {}

    @Post()
    async createProduct() {}

    @Post(':productId/clone')
    async duplicateProduct() {}

    @Patch(':productId')
    async updateProduct() {}

    @Delete(':productId')
    async deleteProduct() {}
}
