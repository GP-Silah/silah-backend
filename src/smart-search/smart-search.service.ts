import {
    BadRequestException,
    HttpException,
    HttpStatus,
    Injectable,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { SmartSearchRequestDto } from './dtos/smartSearchRequest.dto';
import { SmartSearchResponseDto } from './dtos/smartSearchResponse.dto';
import { ItemType } from '@prisma/client';
import axios from 'axios';

@Injectable()
export class SmartSearchService {
    constructor(private readonly prisma: PrismaService) {}

    async getSimilarItems(
        dto: SmartSearchRequestDto,
    ): Promise<SmartSearchResponseDto[]> {
        const { itemId, itemName, itemDescription, itemType, categoryId } = dto;

        // 1. Validate: at least itemId or itemName must exist
        if (!itemId && !itemName) {
            throw new BadRequestException(
                'Either itemId or itemName must be provided',
            );
        }

        let baseItem: any = null;
        let resolvedType: ItemType | null = itemType ?? null;

        // 2. If itemId is given, validate it exists
        if (itemId) {
            if (resolvedType) {
                // Type explicitly provided → only check that table
                if (resolvedType === ItemType.PRODUCT) {
                    baseItem = await this.prisma.product.findUnique({
                        where: { id: itemId },
                    });
                } else if (resolvedType === ItemType.SERVICE) {
                    baseItem = await this.prisma.service.findUnique({
                        where: { id: itemId },
                    });
                }

                if (!baseItem) {
                    throw new BadRequestException(
                        `No item found with the given ID for type ${resolvedType}`,
                    );
                }
            } else {
                // Type not provided → try both tables
                const product = await this.prisma.product.findUnique({
                    where: { id: itemId },
                });
                const service = await this.prisma.service.findUnique({
                    where: { id: itemId },
                });

                if (product) {
                    baseItem = product;
                    resolvedType = ItemType.PRODUCT;
                } else if (service) {
                    baseItem = service;
                    resolvedType = ItemType.SERVICE;
                } else {
                    throw new BadRequestException(
                        `No item found with the given ID`,
                    );
                }
            }

            // Fill missing request fields from DB
            if (!itemName) dto.itemName = baseItem.name;
            if (!dto.itemDescription && baseItem.description) {
                dto.itemDescription = baseItem.description;
            }
        }

        // 3. If categoryId is provided, validate it exists
        let categoryName: string | undefined = undefined;
        if (categoryId) {
            const category = await this.prisma.category.findUnique({
                where: { id: categoryId },
            });
            if (!category) {
                throw new BadRequestException('Invalid categoryId provided');
            }
            categoryName = category.name;

            // Ensure category matches item if both provided
            if (baseItem && baseItem.categoryId !== categoryId) {
                throw new BadRequestException(
                    'Category does not match the item provided',
                );
            }
        }

        try {
            // Build payload for FastAPI
            const payload = {
                item_id: itemId,
                name: dto.itemName,
                description: dto.itemDescription,
                type: resolvedType, // can be null if the request is free-text search with no itemId provided
                category_name: categoryName, // can be null if frontend didn’t provide it
            };

            // Call FastAPI
            const response = await axios.post(
                `${process.env.AI_BACKEND_URL}/similar-search`,
                payload,
            );

            const aiResults = response.data;

            // Validate AI response
            if (!Array.isArray(aiResults)) {
                throw new HttpException(
                    'Invalid response from AI backend',
                    HttpStatus.BAD_GATEWAY,
                );
            }

            // Fetch details from DB based on resolvedType
            let items: any[] = [];
            if (resolvedType === ItemType.PRODUCT) {
                items = await this.prisma.product.findMany({
                    where: { id: { in: aiResults.map((r: any) => r.id) } },
                });
            } else if (resolvedType === ItemType.SERVICE) {
                items = await this.prisma.service.findMany({
                    where: { id: { in: aiResults.map((r: any) => r.id) } },
                });
            } else {
                // If type unknown, fetch both products and services concurrently
                const [products, services] = await Promise.all([
                    this.prisma.product.findMany({
                        where: { id: { in: aiResults.map((r: any) => r.id) } },
                    }),
                    this.prisma.service.findMany({
                        where: { id: { in: aiResults.map((r: any) => r.id) } },
                    }),
                ]);
                items = [...products, ...services];
            }

            // Merge similarity scores from FastAPI with DB items
            return items.map((item) => ({
                item,
                similarityScore:
                    aiResults.find((r: any) => r.id === item.id)
                        ?.similarityScore ?? 0,
            })) as SmartSearchResponseDto[];
        } catch (err: any) {
            console.error('FastAPI request failed:', err.message);
            throw new HttpException(
                'Failed to get similar items from AI backend',
                HttpStatus.BAD_GATEWAY,
            );
        }
    }
}
