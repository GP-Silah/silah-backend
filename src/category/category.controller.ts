import { Controller, Get, Param, Query } from '@nestjs/common';
import { CategoryService } from './category.service';
import { ApiTags } from '@nestjs/swagger';
import {
    ApiDocsGetAllCategories,
    ApiDocsGetCategoryById,
    ApiDocsGetMainCategories,
    ApiDocsGetSubCategories,
} from './category.docts';

@ApiTags('Categories')
@Controller('categories')
export class CategoryController {
    constructor(private readonly categoryService: CategoryService) {}

    @ApiDocsGetAllCategories()
    @Get()
    async getAllCategories(
        @Query('usedFor') usedFor?: 'products' | 'services',
    ) {
        return this.categoryService.getAllCategories(usedFor);
    }

    @ApiDocsGetMainCategories()
    @Get('main')
    async getMainCategories(
        @Query('usedFor') usedFor?: 'products' | 'services',
    ) {
        return this.categoryService.getMainCategories(usedFor);
    }

    @ApiDocsGetSubCategories()
    @Get('sub')
    async getSubCategories(
        @Query('usedFor') usedFor?: 'products' | 'services',
    ) {
        return this.categoryService.getSubCategories(usedFor);
    }

    @ApiDocsGetCategoryById()
    @Get(':id')
    async getCategoryById(@Param('id') id: number) {
        return this.categoryService.getCategoryById(id);
    }
}
