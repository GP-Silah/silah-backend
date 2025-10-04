import { Injectable } from '@nestjs/common';
import { Product, User } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';
import { ProductService } from 'src/product/product.service';
import { ServiceService } from 'src/service/service.service';
import { SupplierService } from 'src/supplier/supplier.service';
import { UserService } from 'src/user/user.service';

@Injectable()
export class SearchService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly userService: UserService,
        private readonly supplierService: SupplierService,
        private readonly productService: ProductService,
        private readonly serviceService: ServiceService,
    ) {}

    async searchUsers(name?: string) {
        // If no name is provided, return all users normally
        if (!name || name.trim() === '') {
            const allUsers = await this.prisma.user.findMany();
            return Promise.all(
                allUsers.map((user) =>
                    this.userService.toUserResponseDTO(user),
                ),
            );
        }

        // FTS + fuzzy search
        const users = await this.prisma.$queryRaw<any[]>`
        SELECT 
            u.id AS "userId",
            u."tapCustomerId",
            u.name,
            u.email,
            u.crn,
            u."businessName",
            u.role,
            u.city,
            u."pfpFileName",
            u."isEmailVerified",
            u."preferredLanguage",
            u."createdAt",
            u."updatedAt"
        FROM "User" u
        WHERE to_tsvector('english', u.name) @@ plainto_tsquery('english', ${name})
            OR u.name % ${name}
        ORDER BY ts_rank(to_tsvector('english', u.name), plainto_tsquery('english', ${name})) DESC,
                similarity(u.name, ${name}) DESC;
        `;

        return Promise.all(
            users.map((user) =>
                this.userService.toUserResponseDTO({
                    ...user,
                    id: user.userId, // map userId → id
                } as User),
            ),
        );
    }

    async searchSuppliers(name?: string, businessName?: string) {
        // If no query is provided, return all suppliers
        if (
            (!name || name.trim() === '') &&
            (!businessName || businessName.trim() === '')
        ) {
            const allSuppliers = await this.prisma.supplier.findMany({
                include: { user: true },
            });

            return Promise.all(
                allSuppliers.map(({ user, ...supplier }) =>
                    this.toSupplierResponseSafe(user, supplier),
                ),
            );
        }

        // FTS + fuzzy search for name or businessName
        const suppliers = await this.prisma.$queryRaw<any[]>`
        SELECT 
            s.id AS "supplierId",
            s."userId",
            s."status",
            s."plan",
            s."isStoreClosed",
            s."storeClosedMsg",
            s."storeBio",
            s."storeBannerFileName",
            s."deliveryFees",
            s."avgRating",
            s."ratingsCount",
            s."usedFreeTrail",
            u.id AS "userId",
            u."tapCustomerId",
            u.name,
            u.email,
            u.crn,
            u."businessName",
            u.role,
            u.city,
            u."pfpFileName",
            u."isEmailVerified",
            u."preferredLanguage",
            u."createdAt",
            u."updatedAt"
        FROM "Supplier" s
        JOIN "User" u ON s."userId" = u.id
        WHERE (
            (${name} IS NOT NULL AND to_tsvector('english', u.name) @@ plainto_tsquery('english', ${name}))
            OR (${name} IS NOT NULL AND u.name % ${name})
            OR (${businessName} IS NOT NULL AND to_tsvector('english', u."businessName") @@ plainto_tsquery('english', ${businessName}))
            OR (${businessName} IS NOT NULL AND u."businessName" % ${businessName})
        )
        ORDER BY 
            ts_rank(to_tsvector('english', u.name), plainto_tsquery('english', ${name})) DESC,
            similarity(u.name, ${name}) DESC;
    `;

        return Promise.all(
            suppliers.map((row) => {
                const user = {
                    id: row.userId,
                    tapCustomerId: row.tapCustomerId,
                    name: row.name,
                    email: row.email,
                    crn: row.crn,
                    businessName: row.businessName,
                    role: row.role,
                    city: row.city,
                    pfpFileName: row.pfpFileName,
                    isEmailVerified: row.isEmailVerified,
                    preferredLanguage: row.preferredLanguage,
                    createdAt: row.createdAt,
                    updatedAt: row.updatedAt,
                };

                const supplier = {
                    id: row.supplierId,
                    userId: row.userId,
                    status: row.status,
                    plan: row.plan,
                    isStoreClosed: row.isStoreClosed,
                    storeClosedMsg: row.storeClosedMsg,
                    storeBio: row.storeBio,
                    storeBannerFileName: row.storeBannerFileName,
                    deliveryFees: row.deliveryFees,
                    avgRating: row.avgRating,
                    ratingsCount: row.ratingsCount,
                    usedFreeTrail: row.usedFreeTrail,
                };

                return this.toSupplierResponseSafe(user, supplier);
            }),
        );
    }

    // Helper to handle async mapping safely
    private async toSupplierResponseSafe(user: any, supplier: any) {
        return this.supplierService.toSupplierResponseDTO(user, supplier);
    }

    async searchProducts(
        name?: string,
        categoryId?: number,
        subCategoryId?: number,
    ) {
        let subCategoryIds: number[] | undefined;

        if (categoryId) {
            // get subcategories under the main category
            const subCategories = await this.prisma.category.findMany({
                where: { parentCategoryId: categoryId },
                select: { id: true },
            });
            subCategoryIds = subCategories.map((c) => c.id);
            if (subCategoryIds.length === 0) {
                // main category has no subcategories → no products
                return [];
            }
        } else if (subCategoryId) {
            subCategoryIds = [subCategoryId];
        }

        // Build SQL WHERE filters dynamically
        const filters: string[] = [];
        const params: any[] = [];

        if (name?.trim()) {
            filters.push(
                `(to_tsvector('english', p.name) @@ plainto_tsquery('english', $${params.length + 1}) OR p.name % $${params.length + 1})`,
            );
            params.push(name);
        }

        if (subCategoryIds) {
            filters.push(`p."categoryId" = ANY($${params.length + 1}::int[])`);
            params.push(subCategoryIds);
        }

        const whereClause = filters.length
            ? `WHERE ${filters.join(' AND ')}`
            : '';

        const query = `
        SELECT
            p.*,
            c.id AS "categoryId",
            c.name AS "categoryName",
            s.id AS "supplierId",
            s."userId" AS "supplierUserId",
            s."status" AS "supplierStatus",
            s."plan" AS "supplierPlan",
            s."isStoreClosed",
            s."storeClosedMsg",
            s."storeBio",
            s."storeBannerFileName",
            s."deliveryFees",
            s."avgRating" AS "supplierAvgRating",
            s."ratingsCount" AS "supplierRatingsCount",
            s."usedFreeTrail",
            u.id AS "userId",
            u."tapCustomerId",
            u.name AS "userName",
            u.email AS "userEmail",
            u."businessName" AS "userBusinessName",
            u.role AS "userRole",
            u.city AS "userCity",
            u."pfpFileName" AS "userPfpFileName",
            u."isEmailVerified" AS "userIsEmailVerified",
            u."preferredLanguage" AS "userPreferredLanguage",
            u."createdAt" AS "userCreatedAt",
            u."updatedAt" AS "userUpdatedAt"
        FROM "Product" p
        JOIN "Category" c ON c.id = p."categoryId"
        LEFT JOIN "Supplier" s ON s.id = p."supplierId"
        LEFT JOIN "User" u ON u.id = s."userId"
        ${whereClause}
        ORDER BY ${name ? `ts_rank(to_tsvector('english', p.name), plainto_tsquery('english', $1)) DESC, similarity(p.name, $1) DESC` : 'p."createdAt" DESC'};
    `;

        const products = await this.prisma.$queryRawUnsafe<any[]>(
            query,
            ...params,
        );

        return Promise.all(
            products.map((row: any) => {
                const product = {
                    ...row,
                    category: { id: row.categoryId, name: row.categoryName },
                    supplier: row.supplierId
                        ? {
                              id: row.supplierId,
                              userId: row.supplierUserId,
                              status: row.supplierStatus,
                              plan: row.supplierPlan,
                              isStoreClosed: row.isStoreClosed,
                              storeClosedMsg: row.storeClosedMsg,
                              storeBio: row.storeBio,
                              storeBannerFileName: row.storeBannerFileName,
                              deliveryFees: row.deliveryFees,
                              avgRating: row.supplierAvgRating,
                              ratingsCount: row.supplierRatingsCount,
                              usedFreeTrail: row.usedFreeTrail,
                              user: {
                                  id: row.userId,
                                  tapCustomerId: row.tapCustomerId,
                                  name: row.userName,
                                  email: row.userEmail,
                                  businessName: row.userBusinessName,
                                  role: row.userRole,
                                  city: row.userCity,
                                  pfpFileName: row.userPfpFileName,
                                  isEmailVerified: row.userIsEmailVerified,
                                  preferredLanguage: row.userPreferredLanguage,
                                  createdAt: row.userCreatedAt,
                                  updatedAt: row.userUpdatedAt,
                              },
                          }
                        : null,
                };
                return this.productService.toProductResponseDto(product);
            }),
        );
    }
}
