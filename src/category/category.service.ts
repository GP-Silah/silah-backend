import { Injectable, NotFoundException } from '@nestjs/common';
import { Category } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';
import { CategoryResponseDto } from './dtos/categoryResponse.dto';
import { TranslationService } from 'src/translation/translation.service';

@Injectable()
export class CategoryService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly translationService: TranslationService,
    ) {}

    /** Helper: fetch user's preferred language */
    async getUserLanguage(userId: string): Promise<'ar' | 'en' | null> {
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
            select: { preferredLanguage: true },
        });
        const lang = user?.preferredLanguage?.toLowerCase();
        return lang === 'ar' || lang === 'en' ? lang : null;
    }

    /** Convert category model to DTO (with recursive translation) */
    private async toCategoryResponse(
        category: Category,
        targetLang?: 'ar' | 'en',
    ): Promise<CategoryResponseDto> {
        // Translate name if targetLang provided
        const translatedName =
            targetLang && targetLang !== 'en'
                ? await this.translationService.translateText(
                      category.name,
                      targetLang,
                  )
                : category.name;

        // Fetch parent category name if it exists
        let parentCategoryDto: { id: number; name: string } | undefined =
            undefined;
        if (category.parentCategoryId) {
            const parent = await this.prisma.category.findUnique({
                where: { id: category.parentCategoryId },
                select: { id: true, name: true },
            });
            if (parent) {
                const parentTranslatedName =
                    targetLang && targetLang !== 'en'
                        ? await this.translationService.translateText(
                              parent.name,
                              targetLang,
                          )
                        : parent.name;

                parentCategoryDto = {
                    id: parent.id,
                    name: parentTranslatedName,
                };
            }
        }

        // Fetch subcategories recursively
        const subcategories = await this.prisma.category.findMany({
            where: { parentCategoryId: category.id },
        });

        const subcategoriesDto: CategoryResponseDto[] = [];
        for (const sub of subcategories) {
            subcategoriesDto.push(
                await this.toCategoryResponse(sub, targetLang),
            );
        }

        return {
            id: category.id,
            name: translatedName,
            usedFor: category.usedFor,
            parentCategory: parentCategoryDto,
            subcategories: subcategoriesDto.length
                ? subcategoriesDto
                : undefined,
        } as CategoryResponseDto;
    }

    async getAllCategories(
        usedFor?: 'products' | 'services',
        targetLang?: 'ar' | 'en',
    ): Promise<CategoryResponseDto[]> {
        // Map the query value to Prisma ItemType
        const usedForEnum =
            usedFor === 'products'
                ? 'PRODUCT'
                : usedFor === 'services'
                  ? 'SERVICE'
                  : undefined;

        // Fetch all main categories (parentCategoryId = null)
        const mainCategories = await this.prisma.category.findMany({
            where: {
                parentCategoryId: null,
                ...(usedForEnum ? { usedFor: usedForEnum } : {}),
            },
        });

        // Map each main category to DTO including subcategories recursively
        const categoriesDto: CategoryResponseDto[] = [];
        for (const category of mainCategories) {
            categoriesDto.push(
                await this.toCategoryResponse(category, targetLang),
            );
        }

        return categoriesDto;
    }

    async getMainCategories(
        usedFor?: 'products' | 'services',
        targetLang?: 'ar' | 'en',
    ): Promise<CategoryResponseDto[]> {
        const usedForEnum =
            usedFor === 'products'
                ? 'PRODUCT'
                : usedFor === 'services'
                  ? 'SERVICE'
                  : undefined;
        const mainCategories = await this.prisma.category.findMany({
            where: {
                parentCategoryId: null,
                ...(usedForEnum ? { usedFor: usedForEnum } : {}),
            },
        });
        const dto: CategoryResponseDto[] = [];
        for (const cat of mainCategories) {
            dto.push(await this.toCategoryResponse(cat, targetLang));
        }
        return dto;
    }

    async getSubCategories(
        usedFor?: 'products' | 'services',
        targetLang?: 'ar' | 'en',
    ): Promise<CategoryResponseDto[]> {
        const usedForEnum =
            usedFor === 'products'
                ? 'PRODUCT'
                : usedFor === 'services'
                  ? 'SERVICE'
                  : undefined;
        const subCategories = await this.prisma.category.findMany({
            where: {
                NOT: { parentCategoryId: null },
                ...(usedForEnum ? { usedFor: usedForEnum } : {}),
            },
        });
        const dto: CategoryResponseDto[] = [];
        for (const cat of subCategories) {
            dto.push(await this.toCategoryResponse(cat, targetLang));
        }
        return dto;
    }

    async getCategoryById(
        id: number,
        targetLang?: 'ar' | 'en',
    ): Promise<CategoryResponseDto> {
        const category = await this.prisma.category.findUnique({
            where: { id },
        });
        if (!category) {
            throw new NotFoundException(`Category with ID ${id} not found`);
        }
        return this.toCategoryResponse(category, targetLang);
    }
}
