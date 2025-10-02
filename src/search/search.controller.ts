import { Controller, Get, Query } from '@nestjs/common';
import { SearchService } from './search.service';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { ApiDocsGetSearchUsers } from './search.docs';

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
    async searchSuppliers(
        @Query('name') name: string,
        @Query('businessName') businessName: string,
    ) {}

    @Get('products')
    async searchProducts(
        @Query('name') name: string,
        @Query('category') categoryId: string,
        @Query('subcategory') subCategoryId: string,
    ) {}

    @Get('services')
    async searchServices(
        @Query('name') name: string,
        @Query('category') categoryId: string,
        @Query('subcategory') subCategoryId: string,
    ) {}

    //TODO: chats srarch
    @Get('chats')
    @ApiOperation({
        deprecated: true,
        summary: 'Not implemented yet',
        description: 'This endpoint is a placeholder and not implemented yet.',
    })
    async searchChats(@Query('query') query: string) {}
}
