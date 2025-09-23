import { Injectable, NotFoundException } from '@nestjs/common';
import { Category } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';
import { CategoryResponseDto } from './dtos/categoryResponse.dto';

@Injectable()
export class CategoryService {
    constructor(private readonly prisma: PrismaService) {}

    private async toCategoryResponse(
        category: Category,
    ): Promise<CategoryResponseDto> {
        // Fetch parent category name if it exists
        let parentCategoryDto: { id: number; name: string } | undefined =
            undefined;
        if (category.parentCategoryId) {
            const parent = await this.prisma.category.findUnique({
                where: { id: category.parentCategoryId },
                select: { id: true, name: true },
            });
            if (parent) {
                parentCategoryDto = { id: parent.id, name: parent.name };
            }
        }

        // Fetch subcategories
        const subcategories = await this.prisma.category.findMany({
            where: { parentCategoryId: category.id },
        });

        // Recursively map subcategories
        const subcategoriesDto: CategoryResponseDto[] = [];
        for (const sub of subcategories) {
            subcategoriesDto.push(await this.toCategoryResponse(sub));
        }

        // Return DTO
        return {
            id: category.id,
            name: category.name,
            usedFor: category.usedFor,
            parentCategory: parentCategoryDto,
            subcategories: subcategoriesDto.length
                ? subcategoriesDto
                : undefined,
        } as CategoryResponseDto;
    }

    async getAllCategories(
        usedFor?: 'products' | 'services',
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
            categoriesDto.push(await this.toCategoryResponse(category));
        }

        return categoriesDto;
    }

    async getMainCategories(
        usedFor?: 'products' | 'services',
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
            dto.push(await this.toCategoryResponse(cat));
        }
        return dto;
    }

    async getSubCategories(
        usedFor?: 'products' | 'services',
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
            dto.push(await this.toCategoryResponse(cat));
        }
        return dto;
    }

    async getCategoryById(id: number): Promise<CategoryResponseDto> {
        const category = await this.prisma.category.findUnique({
            where: { id },
        });
        if (!category) {
            throw new NotFoundException(`Category with ID ${id} not found`);
        }
        return this.toCategoryResponse(category);
    }
}
