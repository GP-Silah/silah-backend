import { Controller, Get, Param, Query, Req, Headers } from '@nestjs/common';
import { CategoryService } from './category.service';
import { ApiTags } from '@nestjs/swagger';
import {
    ApiDocsGetAllCategories,
    ApiDocsGetCategoryById,
    ApiDocsGetMainCategories,
    ApiDocsGetSubCategories,
} from './category.docts';
import { Request } from 'express';

@ApiTags('Categories')
@Controller('categories')
export class CategoryController {
    constructor(private readonly categoryService: CategoryService) {}

    /** Helper function to determine target language */
    private async resolveTargetLang(
        req: Request,
        lang?: 'ar' | 'en',
        langHeader?: 'ar' | 'en',
    ) {
        let targetLang: 'ar' | 'en' = 'en';

        // Priority: query param > header > user preference > default
        if (lang) {
            targetLang = lang;
        } else if (langHeader) {
            targetLang = langHeader;
        } else if (req.tokenData?.sub) {
            const user = await this.categoryService.getUserLanguage(
                req.tokenData.sub,
            );
            if (user) targetLang = user;
        }

        return targetLang;
    }

    @ApiDocsGetAllCategories()
    @Get()
    async getAllCategories(
        @Req() req: Request,
        @Headers('accept-language') langHeader?: 'ar' | 'en',
        @Query('lang') lang?: 'ar' | 'en',
        @Query('usedFor') usedFor?: 'products' | 'services',
    ) {
        const targetLang = await this.resolveTargetLang(req, lang, langHeader);
        return this.categoryService.getAllCategories(usedFor, targetLang);
    }

    @ApiDocsGetMainCategories()
    @Get('main')
    async getMainCategories(
        @Req() req: Request,
        @Headers('accept-language') langHeader?: 'ar' | 'en',
        @Query('lang') lang?: 'ar' | 'en',
        @Query('usedFor') usedFor?: 'products' | 'services',
    ) {
        const targetLang = await this.resolveTargetLang(req, lang, langHeader);
        return this.categoryService.getMainCategories(usedFor, targetLang);
    }

    @ApiDocsGetSubCategories()
    @Get('sub')
    async getSubCategories(
        @Req() req: Request,
        @Headers('accept-language') langHeader?: 'ar' | 'en',
        @Query('lang') lang?: 'ar' | 'en',
        @Query('usedFor') usedFor?: 'products' | 'services',
    ) {
        const targetLang = await this.resolveTargetLang(req, lang, langHeader);
        return this.categoryService.getSubCategories(usedFor, targetLang);
    }

    @ApiDocsGetCategoryById()
    @Get(':id')
    async getCategoryById(
        @Param('id') id: number,
        @Req() req: Request,
        @Headers('accept-language') langHeader?: 'ar' | 'en',
        @Query('lang') lang?: 'ar' | 'en',
    ) {
        const targetLang = await this.resolveTargetLang(req, lang, langHeader);
        return this.categoryService.getCategoryById(id, targetLang);
    }
}
