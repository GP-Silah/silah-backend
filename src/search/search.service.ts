import { Injectable } from '@nestjs/common';
import { SupplierStatus, User } from '@prisma/client';
import { ChatService } from 'src/chat/chat.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { ProductService } from 'src/product/product.service';
import { ServiceService } from 'src/service/service.service';
import { SupplierService } from 'src/supplier/supplier.service';
import { UserService } from 'src/user/user.service';
import { ProductResponseDto } from 'src/product/dtos/productResponse.dto';
import { ServiceResponseDto } from 'src/service/dtos/serviceResponse.dto';

@Injectable()
export class SearchService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly userService: UserService,
        private readonly supplierService: SupplierService,
        private readonly productService: ProductService,
        private readonly serviceService: ServiceService,
        private readonly chatService: ChatService,
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
                where: {
                    isStoreClosed: false,
                    status: SupplierStatus.ACTIVE,
                },
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
        mainCategoryId?: string,
        subCategoryId?: string,
        minPrice: string = '1',
        maxPrice?: string,
        targetLang?: 'ar' | 'en',
    ) {
        // Convert query params safely
        const mainId = mainCategoryId ? Number(mainCategoryId) : undefined;
        const subId = subCategoryId ? Number(subCategoryId) : undefined;
        const minPriceAsNumber =
            minPrice && Number(minPrice) > 0 ? Number(minPrice) : undefined;
        const maxPriceAsNumber =
            maxPrice && Number(maxPrice) > 0 ? Number(maxPrice) : undefined;

        // Sanitize name
        let q = name?.trim()?.replace(/'/g, "''") ?? '';
        if (q.length > 100) q = q.substring(0, 100);

        // 1. Build base where
        const whereClause: any = {
            isDeleted: false,
            isPublished: true,
            supplier: {
                isStoreClosed: false,
                status: SupplierStatus.ACTIVE,
            },
        };

        // 2. Handle category filters
        if (mainId && !subId) {
            const subs = await this.prisma.category.findMany({
                where: { parentCategoryId: mainId },
                select: { id: true },
            });
            if (!subs.length) return [];
            whereClause.categoryId = { in: subs.map((s) => s.id) };
        } else if (subId) {
            const exists = await this.prisma.category.findUnique({
                where: { id: subId },
                select: { id: true },
            });
            if (!exists) return [];
            whereClause.categoryId = subId;
        }

        // 3. Fuzzy search
        let productIds: string[] = [];
        if (q) {
            const query = `
                SELECT p."id", similarity(p."name", '${q}') AS sim
                FROM "Product" p
                JOIN "Supplier" s ON p."supplierId" = s."id"
                WHERE p."isDeleted" = false
                AND p."isPublished" = true
                AND s."isStoreClosed" = false
                AND similarity(p."name", '${q}') > 0.1
                ORDER BY sim DESC
                LIMIT 50;
            `;

            const fuzzyRows =
                await this.prisma.$queryRawUnsafe<{ id: string }[]>(query);
            productIds = fuzzyRows.map((r) => r.id);
            if (!productIds.length) return [];
            whereClause.id = { in: productIds };
        }

        // 4. Apply price filterss
        whereClause.price = {
            ...(minPriceAsNumber !== undefined
                ? { gte: minPriceAsNumber }
                : {}),
            ...(maxPriceAsNumber !== undefined
                ? { lte: maxPriceAsNumber }
                : {}),
        };

        // 5. Fetch products
        let products = await this.prisma.product.findMany({
            where: whereClause,
            include: { supplier: { include: { user: true } }, category: true },
        });

        if (!products.length) return [];

        // 6. Map to DTOs
        return Promise.all(
            products.map((p) =>
                this.productService.toProductResponseDto(p, targetLang),
            ),
        );
    }

    async searchServices(
        name?: string,
        mainCategoryId?: string,
        subCategoryId?: string,
        targetLang?: 'ar' | 'en',
    ) {
        // Convert query params safely
        const mainId = mainCategoryId ? Number(mainCategoryId) : undefined;
        const subId = subCategoryId ? Number(subCategoryId) : undefined;

        // Sanitize name
        let q = name?.trim()?.replace(/'/g, "''") ?? '';
        if (q.length > 100) q = q.substring(0, 100);

        // 1. Build base where
        const whereClause: any = {
            isDeleted: false,
            isPublished: true,
            supplier: {
                isStoreClosed: false,
                status: SupplierStatus.ACTIVE,
            },
        };

        // 2. Handle category filters
        if (mainId && !subId) {
            const subs = await this.prisma.category.findMany({
                where: { parentCategoryId: mainId },
                select: { id: true },
            });
            if (!subs.length) return [];
            whereClause.categoryId = { in: subs.map((s) => s.id) };
        } else if (subId) {
            const exists = await this.prisma.category.findUnique({
                where: { id: subId },
                select: { id: true },
            });
            if (!exists) return [];
            whereClause.categoryId = subId;
        }

        // 3. Fuzzy search
        let servicesIds: string[] = [];
        if (q) {
            const query = `
                SELECT s."id", similarity(s."name", '${q}') AS sim
                FROM "Service" s
                JOIN "Supplier" sp ON s."supplierId" = sp."id"
                WHERE s."isDeleted" = false
                AND s."isPublished" = true
                AND sp."isStoreClosed" = false
                AND similarity(s."name", '${q}') > 0.1
                ORDER BY sim DESC
                LIMIT 50;
            `;

            const fuzzyRows =
                await this.prisma.$queryRawUnsafe<{ id: string }[]>(query);
            servicesIds = fuzzyRows.map((r) => r.id);
            if (!servicesIds.length) return [];
            whereClause.id = { in: servicesIds };
        }

        // 4. Fetch services
        let services = await this.prisma.service.findMany({
            where: whereClause,
            include: { supplier: { include: { user: true } }, category: true },
        });

        if (!services.length) return [];

        // 5. Map to DTOs
        return Promise.all(
            services.map((s) =>
                this.serviceService.toServiceResponseDto(s, targetLang),
            ),
        );
    }

    async searchChats(userId: string, text: string) {
        if (!text || !text.trim()) return [];

        // Sanitize text
        let q = text?.trim()?.replace(/'/g, "''") ?? '';
        if (q.length > 100) q = q.substring(0, 100);

        // Build base where
        const whereClause: any = {};

        // Fuzzy search
        let chatIds: string[] = [];
        if (q) {
            const query = `
                SELECT c."id" AS "chatId", u1."id" AS "user1Id", u2."id" AS "user2Id"
                FROM "Chat" c
                JOIN "User" u1 ON c."user1Id" = u1."id"
                JOIN "User" u2 ON c."user2Id" = u2."id"
                WHERE (c."user1Id" = '${userId}' AND (similarity(u2.name, '${text}') > 0.1 OR similarity(u2."businessName", '${text}') > 0.1))
                OR (c."user2Id" = '${userId}' AND (similarity(u1.name, '${text}') > 0.1 OR similarity(u1."businessName", '${text}') > 0.1))
                ORDER BY GREATEST(similarity(u1.name, '${text}'), similarity(u1."businessName",'${text}'),
                similarity(u2.name, '${text}'), similarity(u2."businessName", '${text}')) DESC
                LIMIT 50;
            `;

            const fuzzyRows =
                await this.prisma.$queryRawUnsafe<{ chatId: string }[]>(query);
            chatIds = fuzzyRows.map((r) => r.chatId);
            if (!chatIds.length) return [];
            whereClause.id = { in: chatIds };
        }

        // Fetch chats
        let chats = await this.prisma.chat.findMany({
            where: whereClause,
            include: {
                user1: { include: { firstChatUser: true } },
                user2: { include: { secondChatUser: true } },
                messages: {
                    orderBy: { createdAt: 'desc' },
                    take: 1,
                },
            },
            orderBy: { updatedAt: 'desc' },
        });

        if (!chats.length) return [];

        return Promise.all(
            chats.map((c) =>
                this.chatService.toChatResponseDto(c as any, userId),
            ),
        );
    }

    async searchSupplierCatalog(userId: string, name: string) {
        if (!name || !name.trim()) return [];

        const supplier = await this.prisma.supplier.findUnique({
            where: { userId },
            select: { id: true },
        });
        if (!supplier) return [];

        // Sanitize text
        let q = name?.trim()?.replace(/'/g, "''") ?? '';
        if (q.length > 100) q = q.substring(0, 100);

        // Build base where
        const productWhereClause: any = {};
        const serviceWhereClause: any = {};

        // Fuzzy search
        let productIds: string[] = [];
        let serviceIds: string[] = [];
        if (q) {
            const productQuery = `
                SELECT "id"
                FROM "Product"
                WHERE "supplierId" = '${supplier.id}'
                AND "isDeleted" = false
                AND similarity("name", '${q}') > 0.1
                ORDER BY similarity("name", '${q}') DESC
                LIMIT 50
            `;

            const fuzzyProductRows =
                await this.prisma.$queryRawUnsafe<{ id: string }[]>(
                    productQuery,
                );
            productIds = fuzzyProductRows.map((r) => r.id);
            if (productIds) productWhereClause.id = { in: productIds };

            const serviceQuery = `
                SELECT "id"
                FROM "Service"
                WHERE "supplierId" = '${supplier.id}'
                AND "isDeleted" = false
                AND similarity("name", '${q}') > 0.1
                ORDER BY similarity("name", '${q}') DESC
                LIMIT 50
            `;

            const fuzzyServiceRows =
                await this.prisma.$queryRawUnsafe<{ id: string }[]>(
                    serviceQuery,
                );
            serviceIds = fuzzyServiceRows.map((r) => r.id);
            if (serviceIds) serviceWhereClause.id = { in: serviceIds };

            if (!productIds && !serviceIds) return [];
        }

        // Fetch products + services
        let products = await this.prisma.product.findMany({
            where: productWhereClause,
            include: { supplier: { include: { user: true } }, category: true },
        });

        let services = await this.prisma.service.findMany({
            where: serviceWhereClause,
            include: { supplier: { include: { user: true } }, category: true },
        });

        if (!products.length && !services.length) return [];

        // Map to DTOs
        let productsDtoPromise: Promise<ProductResponseDto[]> = Promise.resolve(
            [],
        );
        let servicesDtoPromise: Promise<ServiceResponseDto[]> = Promise.resolve(
            [],
        );

        if (products.length > 0) {
            productsDtoPromise = Promise.all(
                products.map((p) =>
                    this.productService.toProductResponseDto(p as any),
                ),
            );
        }

        if (services.length > 0) {
            servicesDtoPromise = Promise.all(
                services.map((s) =>
                    this.serviceService.toServiceResponseDto(s as any),
                ),
            );
        }

        // Wait for results
        const [productsDto, servicesDto] = await Promise.all([
            productsDtoPromise,
            servicesDtoPromise,
        ]);

        // Return according to availability
        if (productsDto.length && servicesDto.length)
            return [...productsDto, ...servicesDto];
        if (productsDto.length) return productsDto;
        if (servicesDto.length) return servicesDto;

        return [];
    }
}
