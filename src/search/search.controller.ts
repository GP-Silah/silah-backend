import { Controller, Get, Query, Req, UseGuards } from '@nestjs/common';
import { SearchService } from './search.service';
import { ApiTags } from '@nestjs/swagger';
import {
    ApiDocsGetSearchChats,
    ApiDocsGetSearchProducts,
    ApiDocsGetSearchServices,
    ApiDocsGetSearchSupplierCatalog,
    ApiDocsGetSearchSuppliers,
    ApiDocsGetSearchUsers,
} from './search.docs';
import { ApiDocsJwtAuthGuard } from 'src/auth/decorators/jwt-auth-guard.docs';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { Request } from 'express';
import { ApiDocsRolesGuard } from 'src/auth/decorators/roles-guard.docs';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { UserRole } from 'src/enums/userRole.enum';
import { RolesGuard } from 'src/auth/guards/roles.guard';

@ApiTags('Search')
@Controller('search')
export class SearchController {
    constructor(private readonly searchService: SearchService) {}

    @Get('users')
    @ApiDocsGetSearchUsers()
    async searchUsers(@Query('name') name?: string) {
        return this.searchService.searchUsers(name);
    }

    @Get('suppliers')
    @ApiDocsGetSearchSuppliers()
    async searchSuppliers(
        @Query('name') name?: string,
        @Query('businessName') businessName?: string,
    ) {
        return this.searchService.searchSuppliers(name, businessName);
    }

    @Get('products')
    @ApiDocsGetSearchProducts()
    async searchProducts(
        @Query('name') name?: string,
        @Query('category') categoryId?: string,
        @Query('subcategory') subCategoryId?: string,
        @Query('minPrice') minPrice?: string,
        @Query('maxPrice') maxPrice?: string,
    ) {
        return this.searchService.searchProducts(
            name,
            categoryId,
            subCategoryId,
            minPrice,
            maxPrice,
        );
    }

    @Get('services')
    @ApiDocsGetSearchServices()
    async searchServices(
        @Query('name') name?: string,
        @Query('category') categoryId?: string,
        @Query('subcategory') subCategoryId?: string,
    ) {
        return this.searchService.searchServices(
            name,
            categoryId,
            subCategoryId,
        );
    }

    @ApiDocsJwtAuthGuard()
    @UseGuards(JwtAuthGuard)
    @Get('chats')
    @ApiDocsGetSearchChats()
    async searchChats(@Req() req: Request, @Query('text') text: string) {
        const userId = req.tokenData!.sub;
        return this.searchService.searchChats(userId, text);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Get('supplier/catalog')
    @ApiDocsGetSearchSupplierCatalog()
    async searchSupplierCatalog(
        @Req() req: Request,
        @Query('name') name: string,
    ) {
        const userId = req.tokenData!.sub;
        return this.searchService.searchSupplierCatalog(userId, name);
    }
}
