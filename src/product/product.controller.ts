import {
    Controller,
    Delete,
    Get,
    Param,
    Patch,
    Post,
    UseGuards,
} from '@nestjs/common';
import { ProductService } from './product.service';
import { ApiTags } from '@nestjs/swagger';
import { ApiJwtAuthGuard } from 'src/auth/decorators/api-jwt-auth-guard.docs';
import { ApiRolesGuard } from 'src/auth/decorators/api-roles-guard.docs';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { UserRole } from 'src/enums/userRole.enum';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';

@ApiTags('Products')
@Controller('products')
export class ProductController {
    constructor(private readonly productService: ProductService) {}

    @Get()
    async getAllProducts() {
        return this.productService.getAllProducts();
    }

    @Get(':productId')
    async getProductById(@Param('productId') productId: string) {
        return this.productService.getProductById(productId);
    }

    @Get('supplier/:supplierId')
    async getAllSupplierProducts(@Param('souplierId') supplierId: string) {
        return this.productService.getAllSupplierProducts(supplierId);
    }

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Post()
    async createProduct() {}

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Post(':productId/clone')
    async duplicateProduct() {}

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Patch(':productId')
    async updateProduct() {}

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Delete(':productId/image/:fileName')
    async deleteProductImage() {}

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Delete(':productId')
    async deleteProduct() {}
}
