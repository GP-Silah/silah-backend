import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { CategoryResponseDto } from './dtos/categoryResponse.dto';
import { TranslationService } from 'src/translation/translation.service';
import { Category } from '@prisma/client';

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

    /** Builds a nested tree from a flat list */
    private buildCategoryTree(categories: Category[]): CategoryResponseDto[] {
        const map = new Map<number, CategoryResponseDto>();

        for (const cat of categories) {
            map.set(cat.id, {
                id: cat.id,
                name: cat.name,
                usedFor: cat.usedFor,
                parentCategory: undefined,
                subcategories: [],
            });
        }

        const roots: CategoryResponseDto[] = [];

        for (const cat of categories) {
            const dto = map.get(cat.id)!;
            if (cat.parentCategoryId) {
                const parent = map.get(cat.parentCategoryId);
                if (parent) {
                    parent.subcategories!.push(dto);
                    dto.parentCategory = { id: parent.id, name: parent.name };
                }
            } else {
                roots.push(dto);
            }
        }

        return roots;
    }

    /** Batch-translate category names (only if needed) */
    private async translateCategories(
        categories: Category[],
        targetLang?: 'ar' | 'en',
    ): Promise<Category[]> {
        if (!targetLang || targetLang === 'en') return categories;

        const uniqueNames = Array.from(new Set(categories.map((c) => c.name)));
        const translated = await this.translationService.translateBatch(
            uniqueNames,
            targetLang,
        );
        const translatedMap = new Map(
            uniqueNames.map((n, i) => [n, translated[i]]),
        );

        return categories.map((c) => ({
            ...c,
            name: translatedMap.get(c.name) || c.name,
        }));
    }

    /** ✅ Get all categories (with tree + translations) */
    async getAllCategories(
        usedFor?: 'products' | 'services',
        targetLang?: 'ar' | 'en',
    ): Promise<CategoryResponseDto[]> {
        const usedForEnum =
            usedFor === 'products'
                ? 'PRODUCT'
                : usedFor === 'services'
                  ? 'SERVICE'
                  : undefined;

        let categories = await this.prisma.category.findMany({
            where: usedForEnum ? { usedFor: usedForEnum } : {},
        });

        categories = await this.translateCategories(categories, targetLang);
        return this.buildCategoryTree(categories);
    }

    /** ✅ Get main categories (with their subcategories) */
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

        // Fetch ALL categories, not only main
        let categories = await this.prisma.category.findMany({
            where: usedForEnum ? { usedFor: usedForEnum } : {},
        });

        categories = await this.translateCategories(categories, targetLang);
        const tree = this.buildCategoryTree(categories);

        // Return only the main roots
        return tree;
    }

    /** ✅ Get subcategories (flat list) */
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

        let categories = await this.prisma.category.findMany({
            where: {
                NOT: { parentCategoryId: null },
                ...(usedForEnum ? { usedFor: usedForEnum } : {}),
            },
        });

        categories = await this.translateCategories(categories, targetLang);

        // Attach parent info manually
        const parents = await this.prisma.category.findMany({
            select: { id: true, name: true },
        });
        const parentMap = new Map(parents.map((p) => [p.id, p.name]));

        return categories.map((cat) => ({
            id: cat.id,
            name: cat.name,
            usedFor: cat.usedFor,
            parentCategory: cat.parentCategoryId
                ? {
                      id: cat.parentCategoryId,
                      name: parentMap.get(cat.parentCategoryId) ?? '',
                  }
                : undefined,
        }));
    }

    /** ✅ Get category by ID (with sub-tree) */
    async getCategoryById(
        id: number,
        targetLang?: 'ar' | 'en',
    ): Promise<CategoryResponseDto> {
        const category = await this.prisma.category.findUnique({
            where: { id },
        });
        if (!category)
            throw new NotFoundException(`Category with ID ${id} not found`);

        let categories = await this.prisma.category.findMany();
        categories = await this.translateCategories(categories, targetLang);
        const fullTree = this.buildCategoryTree(categories);

        // Recursively search
        const findCategory = (
            nodes: CategoryResponseDto[],
        ): CategoryResponseDto | undefined => {
            for (const node of nodes) {
                if (node.id === id) return node;
                const found =
                    node.subcategories && findCategory(node.subcategories);
                if (found) return found;
            }
            return undefined;
        };

        const result = findCategory(fullTree);
        if (!result)
            throw new NotFoundException(
                `Category with ID ${id} not found in tree`,
            );
        return result;
    }
}
