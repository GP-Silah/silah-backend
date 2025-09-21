import { UpdateSupplierDto } from './dtos/updateSupplier.dto';
import {
    BadRequestException,
    Injectable,
    NotFoundException,
} from '@nestjs/common';
import { StoreStatus, Supplier, User } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';
import { SupplierResponseDto } from './dtos/supplierResponse.dto';
import { FileService } from 'src/file/file.service';
import { UserService } from 'src/user/user.service';
import { StorefrontResponseDto } from './dtos/storefrontResponse.dto';

@Injectable()
export class SupplierService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly fileService: FileService,
        private readonly userService: UserService,
    ) {}

    /**
     * Converts Prisma User and Supplier models into a SupplierResponseDto.
     *
     * @param {User} user - The user object from the database.
     * @param {Supplier} supplier - The supplier object from the database.
     * @returns {Promise<SupplierResponseDto>} A supplier DTO formatted for responses.
     */
    async toSupplierResponseDTO(
        user: User,
        supplier: Supplier,
    ): Promise<SupplierResponseDto> {
        // Fetch categories the supplier has marked as favorite
        const favoriteCategories = await this.getSupplierFavoriteCategories(
            user.id,
        );

        // Fetch signed file URL for banner if one exists
        const bannerUrl = supplier.storeBannerFileName
            ? await this.fileService.getFileUrl(supplier.storeBannerFileName)
            : '';

        return {
            user: await this.userService.toUserResponseDTO(user),
            supplierId: supplier.id,
            supplierName: user.name,
            supplierEmail: user.email,
            businessName: user.businessName,
            city: user.city,
            storeStatus: supplier.isStoreClosed
                ? StoreStatus.CLOSED
                : StoreStatus.OPEN,
            storeClosedMsg: supplier.storeClosedMsg,
            storeBio: supplier.storeBio || '',
            storeBannerFileName: supplier.storeBannerFileName || '',
            storeBannerFileUrl: bannerUrl || '',
            deliveryFees: supplier.deliveryFees,
            avgRating: supplier.avgRating,
            ratingsCount: supplier.ratingsCount,
            usedFreeTrail: supplier.usedFreeTrail,
            supplierStatus: supplier.status,
            plan: supplier.plan,
            favoriteCategories,
        };
    }

    /**
     * Converts Prisma User and Supplier models into a StorefrontResponseDto.
     *
     * @param {User} user - The user object from the database.
     * @param {Supplier} supplier - The supplier object from the database.
     * @returns {Promise<StorefrontResponseDto>} A storefront DTO formatted for responses.
     */
    async toStorefrontResponseDTO(
        user: User,
        supplier: Supplier,
    ): Promise<StorefrontResponseDto> {
        // Fetch signed file URL for banner if one exists
        const bannerUrl = supplier.storeBannerFileName
            ? await this.fileService.getFileUrl(supplier.storeBannerFileName)
            : '';

        return {
            supplierId: supplier.id,
            supplierName: user.name,
            supplierEmail: user.email,
            businessName: user.businessName,
            city: user.city,
            storeStatus: supplier.isStoreClosed
                ? StoreStatus.CLOSED
                : StoreStatus.OPEN,
            storeClosedMsg: supplier.storeClosedMsg,
            storeBio: supplier.storeBio || '',
            storeBannerFileName: supplier.storeBannerFileName || '',
            storeBannerFileUrl: bannerUrl || '',
            deliveryFees: supplier.deliveryFees,
            avgRating: supplier.avgRating,
            ratingsCount: supplier.ratingsCount,
            supplierStatus: supplier.status,
        };
    }

    /**
     * Validates a list of category IDs by checking if they exist in the database.
     * Converts valid category IDs into integers for storage.
     *
     * @private
     * @param {number[]} payload - Array of category IDs to validate.
     * @throws {BadRequestException} If any category IDs do not exist in the database.
     * @returns {Promise<number[]>} Array of valid category IDs.
     */
    private async validateSupplierCategories(
        payload: number[],
    ): Promise<number[]> {
        if (payload.length === 0) return [];

        const categories = await this.prisma.category.findMany({
            where: { id: { in: payload } },
        });

        if (categories.length !== payload.length) {
            const foundIds = categories.map((c) => c.id);
            const missing = payload.filter((id) => !foundIds.includes(id));
            throw new BadRequestException(
                `These category IDs are invalid: ${missing.join(', ')}`,
            );
        }

        return categories.map((c) => c.id);
    }

    /**
     * Retrieves all favorite category IDs for a given supplier.
     *
     * @param {string} userId - The ID of the user.
     * @throws {NotFoundException} If the supplier is not found.
     * @returns {Promise<{id: number; name: string}[]>} Array of category objects with IDs and names.
     */
    async getSupplierFavoriteCategories(
        userId: string,
    ): Promise<{ id: number; name: string }[]> {
        const supplierWithCategories = await this.prisma.supplier.findUnique({
            where: { userId },
            include: { categories: { include: { category: true } } },
        });
        if (!supplierWithCategories) {
            throw new NotFoundException(
                'Supplier not found when fetching favorite categories',
            );
        }
        return supplierWithCategories.categories.map((sc) => ({
            id: sc.category.id,
            name: sc.category.name,
        }));
    }

    /**
     * Toggles a category in the supplier's favorite categories.
     *
     * @param {string} supplierId - The supplier's unique ID.
     * @param {number} categoryId - The category's unique ID.
     * @returns {Promise<string>} Message indicating the result.
     */
    async toggleFavoriteCategory(userId: string, categoryId: number) {
        if (!categoryId || categoryId <= 0) {
            throw new BadRequestException('Invalid category ID provided.');
        }
        // Validate category existence
        const valideCategories = await this.validateSupplierCategories([
            categoryId,
        ]);
        if (!valideCategories.includes(categoryId)) {
            throw new BadRequestException(
                `Category with ID ${categoryId} does not exist.`,
            );
        }
        // get the supplier ID
        const supplier = await this.prisma.supplier.findUnique({
            where: { userId },
        });
        if (!supplier) {
            throw new NotFoundException('Supplier not found.');
        }
        // Check if category is already in favorites
        const existing = await this.prisma.supplierFavoriteCategory.findUnique({
            where: {
                supplierId_categoryId: {
                    supplierId: supplier.id,
                    categoryId,
                },
            },
        });
        if (existing) {
            // If exists → remove it
            await this.prisma.supplierFavoriteCategory.delete({
                where: {
                    supplierId_categoryId: {
                        supplierId: supplier.id,
                        categoryId,
                    },
                },
            });
            return {
                message: 'Category removed from favorites.',
                favoriteCategories:
                    await this.getSupplierFavoriteCategories(userId),
            };
        } else {
            // If not exists → add it
            await this.prisma.supplierFavoriteCategory.create({
                data: {
                    supplierId: supplier.id,
                    categoryId,
                },
            });
            return {
                message: 'Category added to favorites.',
                favoriteCategories:
                    await this.getSupplierFavoriteCategories(userId),
            };
        }
    }

    /**
     * Retrieves a supplier data including linked user info.
     * @param {string} id - The supplier ID.
     * @throws {NotFoundException} If the supplier with the given ID is not found.
     * @returns {Promise<SupplierResponseDto>} The supplier DTO formatted for responses.
     */
    async getSupplierData(userId: string): Promise<SupplierResponseDto> {
        const supplier = await this.prisma.supplier.findUnique({
            where: { userId },
            include: { user: true }, // because we need user fields
        });
        if (!supplier) {
            throw new NotFoundException(`Supplier with id ${userId} not found`);
        }
        return this.toSupplierResponseDTO(supplier.user, supplier);
    }

    async getSupplierStoreData(userId: string): Promise<StorefrontResponseDto> {
        const supplier = await this.prisma.supplier.findUnique({
            where: { userId },
            include: { user: true }, // because we need user fields
        });
        if (!supplier) {
            throw new NotFoundException(`Supplier with id ${userId} not found`);
        }
        return this.toStorefrontResponseDTO(supplier.user, supplier);
    }

    async updateSupplierData() {}

    async updateStoreBanner(file: Express.Multer.File, userId: string) {
        const fileName = await this.fileService.uploadFile(file);
        await this.prisma.supplier.update({
            where: { userId },
            data: { storeBannerFileName: fileName },
        });
        return {
            message: 'Store banner updated successfully',
            storeBannerFileName: fileName,
        };
    }

    async deleteStoreBanner(userId: string) {
        const supplier = await this.prisma.supplier.findUnique({
            where: { userId },
        });
        if (!supplier) {
            throw new NotFoundException('Supplier not found.');
        }
        if (!supplier.storeBannerFileName) {
            throw new BadRequestException('No store banner to delete.');
        }
        // Future Work ?: Delete the file from the storage (R2)
        await this.prisma.supplier.update({
            where: { userId },
            data: { storeBannerFileName: null },
        });
        return { message: 'Store banner deleted successfully' };
    }

    async getStoreBanner(id: string) {
        const supplier = await this.prisma.supplier.findUnique({
            where: { id },
        });
        if (!supplier || !supplier.storeBannerFileName) {
            throw new NotFoundException(
                'No store banner found for this store.',
            );
        }
        const fileUrl = await this.fileService.getFileUrl(
            supplier.storeBannerFileName,
        );
        return { storeBannerFileUrl: fileUrl };
    }

    async getAllSuppliers() {}

    async getSupplierDataById(id: string): Promise<SupplierResponseDto> {
        const supplier = await this.prisma.supplier.findUnique({
            where: { id },
            include: { user: true }, // because we need user fields
        });
        if (!supplier) {
            throw new NotFoundException(`Supplier with id ${id} not found`);
        }
        return this.toSupplierResponseDTO(supplier.user, supplier);
    }

    async getSupplierStoreDataById(id: string): Promise<StorefrontResponseDto> {
        const supplier = await this.prisma.supplier.findUnique({
            where: { id },
            include: { user: true }, // because we need user fields
        });
        if (!supplier) {
            throw new NotFoundException(`Supplier with id ${id} not found`);
        }
        return this.toStorefrontResponseDTO(supplier.user, supplier);
    }
}
