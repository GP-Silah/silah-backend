import { Controller, Get, Query } from '@nestjs/common';
import { SearchService } from './search.service';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import {
    ApiDocsGetSearchProducts,
    ApiDocsGetSearchServices,
    ApiDocsGetSearchSuppliers,
    ApiDocsGetSearchUsers,
} from './search.docs';

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

    //TODO: chats srarch
    @Get('chats')
    @ApiOperation({
        deprecated: true,
        summary: 'Not implemented yet',
        description: 'This endpoint is a placeholder and not implemented yet.',
    })
    async searchChats(@Query('query') query: string) {}
}
