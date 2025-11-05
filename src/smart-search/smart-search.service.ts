import {
    BadRequestException,
    HttpException,
    HttpStatus,
    Injectable,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { SmartSearchRequestDto } from './dtos/smartSearchRequest.dto';
import { SmartSearchResponseDto } from './dtos/smartSearchResponse.dto';
import { ItemType, SupplierStatus } from '@prisma/client';
import axios from 'axios';

@Injectable()
export class SmartSearchService {
    constructor(private readonly prisma: PrismaService) {}

    /** Helper: fetch user's preferred language */
    async getUserLanguage(userId: string): Promise<'ar' | 'en' | null> {
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
            select: { preferredLanguage: true },
        });
        const lang = user?.preferredLanguage?.toLowerCase();
        return lang === 'ar' || lang === 'en' ? lang : null;
    }

    async getSimilarItems(
        dto: SmartSearchRequestDto,
        targetLang?: 'ar' | 'en',
    ): Promise<SmartSearchResponseDto[]> {
        const { itemId, text } = dto;

        // 1. Validate: at least itemId or itemName must exist
        if (!itemId && !text) {
            throw new BadRequestException(
                'Either itemId or text must be provided',
            );
        }

        let item;
        let itemType;
        let embedding;
        let productPayloads: any[] = [];
        let servicePayloads: any[] = [];

        // 2. If itemId is given, validate it exists
        if (itemId) {
            // try both tables
            const product = await this.prisma.product.findFirst({
                where: {
                    id: itemId,
                    isDeleted: false,
                    isPublished: true,
                    supplier: {
                        isStoreClosed: false,
                        status: SupplierStatus.ACTIVE,
                    },
                },
                include: {
                    supplier: { include: { user: true } },
                    category: true,
                },
            });
            const service = await this.prisma.service.findFirst({
                where: {
                    id: itemId,
                    isDeleted: false,
                    isPublished: true,
                    supplier: {
                        isStoreClosed: false,
                        status: SupplierStatus.ACTIVE,
                    },
                },
                include: {
                    supplier: { include: { user: true } },
                    category: true,
                },
            });

            if (product) {
                item = product;
                itemType = ItemType.PRODUCT;

                // fetch all products
                const allProducts = await this.prisma.product.findMany({
                    where: {
                        isDeleted: false,
                        isPublished: true,
                        supplier: {
                            isStoreClosed: false,
                            status: SupplierStatus.ACTIVE,
                        },
                    },
                    include: { category: true },
                });

                productPayloads = await Promise.all(
                    allProducts.map(async (p) => ({
                        id: p.id,
                        name: p.name,
                        description: p.description ?? null,
                        category_name: p.category!.name,
                        embedding: await this.ensureEmbedding({
                            id: p.id,
                            name: p.name,
                            description: p.description,
                            category: p.category,
                            type: ItemType.PRODUCT,
                        }),
                    })),
                );
            } else if (service) {
                item = service;
                itemType = ItemType.SERVICE;

                // fetch all services
                const allServices = await this.prisma.service.findMany({
                    where: {
                        isDeleted: false,
                        isPublished: true,
                        supplier: {
                            isStoreClosed: false,
                            status: SupplierStatus.ACTIVE,
                        },
                    },
                    include: { category: true },
                });

                servicePayloads = await Promise.all(
                    allServices.map(async (s) => ({
                        id: s.id,
                        name: s.name,
                        description: s.description ?? null,
                        category_name: s.category!.name,
                        embedding: await this.ensureEmbedding({
                            id: s.id,
                            name: s.name,
                            description: s.description,
                            category: s.category,
                            type: ItemType.SERVICE,
                        }),
                    })),
                );
            } else {
                throw new BadRequestException(
                    `No item found with the given ID`,
                );
            }

            embedding = await this.ensureEmbedding({
                id: itemId,
                name: item.name,
                description: item.description,
                category: item.category,
                type: itemType,
            });

            if (!embedding) {
                throw new BadRequestException(
                    `Embedding not found for item ${itemId} (${itemType})`,
                );
            }
        }

        // Fill missing request fields from DB
        if (!text) dto.text = item.name;

        if (!itemId) {
            const [allProducts, allServices] = await Promise.all([
                this.prisma.product.findMany({
                    where: {
                        isDeleted: false,
                        isPublished: true,
                        supplier: {
                            isStoreClosed: false,
                            status: SupplierStatus.ACTIVE,
                        },
                    },
                    include: { category: true },
                }),
                this.prisma.service.findMany({
                    where: {
                        isDeleted: false,
                        isPublished: true,
                        supplier: {
                            isStoreClosed: false,
                            status: SupplierStatus.ACTIVE,
                        },
                    },
                    include: { category: true },
                }),
            ]);

            productPayloads = await Promise.all(
                allProducts.map(async (p) => ({
                    id: p.id,
                    name: p.name,
                    description: p.description ?? null,
                    category_name: p.category?.name ?? null,
                    embedding: await this.ensureEmbedding({
                        id: p.id,
                        name: p.name,
                        description: p.description,
                        category: p.category,
                        type: ItemType.PRODUCT,
                    }),
                })),
            );

            servicePayloads = await Promise.all(
                allServices.map(async (s) => ({
                    id: s.id,
                    name: s.name,
                    description: s.description ?? null,
                    category_name: s.category?.name ?? null,
                    embedding: await this.ensureEmbedding({
                        id: s.id,
                        name: s.name,
                        description: s.description,
                        category: s.category,
                        type: ItemType.SERVICE,
                    }),
                })),
            );
        }

        // Build payload for FastAPI
        let payload;

        if (itemType === ItemType.PRODUCT) {
            payload = {
                text: dto.text,
                item_id: itemId,
                embedding,
                candidates: productPayloads,
            };
        } else if (itemType === ItemType.SERVICE) {
            payload = {
                text: dto.text,
                item_id: itemId,
                embedding,
                candidates: servicePayloads,
            };
        } else {
            // If itemType is unknown (free-text search with no itemId), send both products and services
            payload = {
                text: dto.text,
                item_id: null,
                embedding: null,
                candidates: [...productPayloads, ...servicePayloads],
            };
        }

        // Call FastAPI
        let aiResults: any[];
        try {
            const response = await axios.post(
                `${process.env.AI_BACKEND_URL}/similar-search`,
                payload,
            );
            aiResults = response.data;
        } catch (err: any) {
            console.error('FastAPI request failed:', err.message);
            throw new HttpException(
                'AI backend is unavailable',
                HttpStatus.BAD_GATEWAY,
            );
        }

        // Validate AI response
        if (
            !Array.isArray(aiResults) ||
            !aiResults.every((r) => r.id && typeof r.rank === 'number')
        ) {
            throw new HttpException(
                'Invalid AI response format',
                HttpStatus.BAD_GATEWAY,
            );
        }

        // Fetch details from DB based on resolvedType
        let items: any[] = [];
        if (itemType === ItemType.PRODUCT) {
            items = await this.prisma.product.findMany({
                where: { id: { in: aiResults.map((r: any) => r.id) } },
                include: {
                    supplier: { include: { user: true } },
                    category: true,
                },
            });
        } else if (itemType === ItemType.SERVICE) {
            items = await this.prisma.service.findMany({
                where: { id: { in: aiResults.map((r: any) => r.id) } },
                include: {
                    supplier: { include: { user: true } },
                    category: true,
                },
            });
        } else {
            // If type unknown, fetch both products and services concurrently
            const [products, services] = await Promise.all([
                this.prisma.product.findMany({
                    where: { id: { in: aiResults.map((r: any) => r.id) } },
                    include: {
                        supplier: { include: { user: true } },
                        category: true,
                    },
                }),
                this.prisma.service.findMany({
                    where: { id: { in: aiResults.map((r: any) => r.id) } },
                    include: {
                        supplier: { include: { user: true } },
                        category: true,
                    },
                }),
            ]);
            items = [...products, ...services];
        }

        // Merge ranking score from FastAPI with DB items
        return items
            .map((item) => {
                const match = aiResults.find((r: any) => r.id === item.id);
                if (!match) return null; // filter out invalid IDs
                return { text: dto.text, item, rank: match.rank };
            })
            .filter(Boolean) as SmartSearchResponseDto[];
    }

    // --- Embedding helpers
    private async ensureEmbedding(item: {
        id: string;
        name: string;
        description?: string | null;
        category?: { name: string | null };
        type: ItemType;
    }) {
        // Try to fetch existing embedding
        let embeddingRecord = await this.prisma.itemEmbedding.findUnique({
            where: {
                itemId_itemType: {
                    itemId: item.id,
                    itemType: item.type,
                },
            },
        });

        if (!embeddingRecord) {
            // If not found, generate & store it
            await this.generateAndStoreEmbedding({
                itemId: item.id,
                itemType: item.type,
                name: item.name,
                description: item.description ?? null,
                categoryName: item.category?.name ?? '',
            });

            // Fetch again
            embeddingRecord = await this.prisma.itemEmbedding.findUnique({
                where: {
                    itemId_itemType: {
                        itemId: item.id,
                        itemType: item.type,
                    },
                },
            });
        }

        return embeddingRecord?.embedding ?? null;
    }

    async generateAndStoreEmbedding(params: {
        itemId: string;
        itemType: ItemType;
        name: string;
        categoryName: string;
        description?: string | null;
    }): Promise<void> {
        const { itemId, itemType, name, description, categoryName } = params;

        try {
            // 1. Call FastAPI to generate embedding
            const response = await axios.post(
                `${process.env.AI_BACKEND_URL}/embed`,
                {
                    name,
                    description: description ?? null,
                    category_name: categoryName,
                },
            );

            const embedding = response.data?.embedding;
            if (!embedding || !Array.isArray(embedding)) {
                throw new Error('Invalid embedding response from AI backend');
            }

            // 2. Upsert into DB
            await this.prisma.itemEmbedding.upsert({
                where: {
                    itemId_itemType: {
                        itemId,
                        itemType,
                    },
                },
                update: {
                    embedding,
                },
                create: {
                    itemId,
                    itemType,
                    embedding,
                },
            });
        } catch (err: any) {
            console.error('Embedding generation failed:', err.message);
            throw new HttpException(
                'Failed to generate embedding for item',
                HttpStatus.BAD_GATEWAY,
            );
        }
    }
}
