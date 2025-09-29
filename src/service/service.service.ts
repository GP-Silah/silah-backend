import {
    BadRequestException,
    Injectable,
    NotFoundException,
} from '@nestjs/common';
import { Category, Service, Supplier, User } from '@prisma/client';
import { FileService } from 'src/file/file.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { SupplierService } from 'src/supplier/supplier.service';
import { TranslationService } from 'src/translation/translation.service';
import { ServiceResponseDto } from './dtos/serviceResponse.dto';
import { CreateServiceDto } from './dtos/createService.dto';
import { UpdateServiceDto } from './dtos/updateService.dto';

@Injectable()
export class ServiceService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly fileService: FileService,
        private readonly supplierService: SupplierService,
        private readonly translationService: TranslationService,
    ) {}

    async toServiceResponseDto(
        service: Service & {
            supplier?: (Supplier & { user: User }) | null;
            category: Category;
        },
        targetLang?: 'ar' | 'en',
    ): Promise<ServiceResponseDto & { targetLang?: string }> {
        // Supplier DTO
        const supplierDto = service.supplier
            ? await this.supplierService.toSupplierResponseDTO(
                  service.supplier.user,
                  service.supplier,
              )
            : null;

        // Signed URLs
        const imagesFilesUrls = await Promise.all(
            service.imagesFilesNames.map((name) =>
                this.fileService.getFileUrl(name),
            ),
        );

        let name = service.name;
        let description = service.description;

        // Only translate if targetLang is provided
        if (targetLang) {
            name = await this.translationService.translateText(
                service.name,
                targetLang,
            );
            description = await this.translationService.translateText(
                service.description,
                targetLang,
            );
        }

        return {
            serviceId: service.id,
            supplierId: service.supplierId ?? null,
            supplier: supplierDto,
            name,
            description,
            price: service.price,
            isPriceNegotiable: service.isPriceNegotiable,
            category: {
                id: service.categoryId,
                name: service.category.name,
            },
            imagesFilesNames: service.imagesFilesNames,
            imagesFilesUrls,
            serviceAvailability: service.serviceAvailability,
            isPublished: service.isPublished,
            wishlistCount: service.wishlistCount,
            avgRating: service.avgRating,
            ratingsCount: service.ratingsCount,
            createdAt: service.createdAt,
            updatedAt: service.updatedAt,
            isDeleted: service.isDeleted,
            deletedAt: service.deletedAt ?? undefined,
            ...(targetLang ? { targetLang } : {}), // include targetLang only if translated
        };
    }

    async getAllServices(
        targetLang: 'ar' | 'en',
    ): Promise<ServiceResponseDto[]> {
        const services = await this.prisma.service.findMany({
            where: { isDeleted: false, isPublished: true },
            include: {
                supplier: { include: { user: true } },
                category: true,
            },
        });

        return await Promise.all(
            services.map((service) =>
                this.toServiceResponseDto(service, targetLang),
            ),
        );
    }

    async getServiceById(
        serviceId: string,
        targetLang: 'ar' | 'en',
    ): Promise<ServiceResponseDto> {
        const service = await this.prisma.service.findUnique({
            where: { id: serviceId },
            include: {
                supplier: { include: { user: true } },
                category: true,
            },
        });
        if (!service) {
            throw new NotFoundException(
                `Service with id ${serviceId} not found`,
            );
        }
        return this.toServiceResponseDto(service, targetLang);
    }

    async getAllSupplierServices(
        supplierId: string,
        targetLang: 'ar' | 'en',
    ): Promise<ServiceResponseDto[]> {
        const services = await this.prisma.service.findMany({
            where: { supplierId, isDeleted: false },
            include: {
                supplier: { include: { user: true } },
                category: true,
            },
        });
        return Promise.all(
            services.map((s) => this.toServiceResponseDto(s, targetLang)),
        );
    }

    async createService(
        userId: string,
        dto: CreateServiceDto,
        files: Express.Multer.File[],
    ): Promise<ServiceResponseDto> {
        // 1. Check supplier
        const supplier = await this.prisma.supplier.findUnique({
            where: { userId },
        });
        if (!supplier) {
            throw new NotFoundException('Supplier not found');
        }

        // 2. Validate image count (1–10 for services)
        if (!files || files.length === 0) {
            throw new BadRequestException(
                'At least one service image is required',
            );
        }
        if (files.length > 10) {
            throw new BadRequestException(
                'A maximum of 10 service images is allowed',
            );
        }

        // 3. Validate category
        const category = await this.prisma.category.findUnique({
            where: { id: dto.categoryId },
        });
        if (!category) {
            throw new NotFoundException('Category not found');
        }

        // Must be for services
        if (category.usedFor !== 'SERVICE') {
            throw new BadRequestException(
                'This category is not valid for services',
            );
        }

        // 4. Upload images to R2
        const uploadedFileNames = await Promise.all(
            files.map((file) => this.fileService.uploadFile(file)),
        );

        // 5. Create service
        const service = await this.prisma.service.create({
            data: {
                supplierId: supplier.id,
                name: dto.name,
                description: dto.description,
                price: dto.price,
                isPriceNegotiable: dto.isPriceNegotiable ?? false,
                categoryId: dto.categoryId,
                imagesFilesNames: uploadedFileNames,
                serviceAvailability: dto.serviceAvailability,
                isPublished: dto.isPublished ?? false,
            },
        });

        // 6. Return full DTO
        const fullService = await this.prisma.service.findUnique({
            where: { id: service.id },
            include: {
                supplier: { include: { user: true } },
                category: true,
            },
        });

        return this.toServiceResponseDto(fullService!);
    }

    async duplicateService(userId: string, serviceId: string) {
        // 1. Check supplier
        const supplier = await this.prisma.supplier.findUnique({
            where: { userId },
        });
        if (!supplier) {
            throw new NotFoundException('Supplier not found');
        }

        // 2. Find the original service
        const originalService = await this.prisma.service.findUnique({
            where: { id: serviceId, supplierId: supplier.id },
        });
        if (!originalService) {
            throw new NotFoundException('Service not found');
        }

        // 3. Duplicate the service
        const duplicatedService = await this.prisma.service.create({
            data: {
                supplierId: supplier.id,
                name: `${originalService.name} (Copy)`,
                description: originalService.description,
                price: originalService.price,
                isPriceNegotiable: originalService.isPriceNegotiable,
                categoryId: originalService.categoryId,
                imagesFilesNames: originalService.imagesFilesNames,
                serviceAvailability: originalService.serviceAvailability,
                isPublished: false, // don’t publish a copy by default
            },
        });

        // 4. Query back with relations (required for toServiceResponseDto)
        const fullDuplicatedService = await this.prisma.service.findUnique({
            where: { id: duplicatedService.id },
            include: {
                supplier: { include: { user: true } },
                category: true,
            },
        });

        return this.toServiceResponseDto(fullDuplicatedService!);
    }

    // Update service fields only (no images)
    async updateService(
        userId: string,
        serviceId: string,
        dto: UpdateServiceDto,
    ) {
        // 1. Check supplier
        const supplier = await this.prisma.supplier.findUnique({
            where: { userId },
        });
        if (!supplier) {
            throw new NotFoundException('Supplier not found');
        }

        // 2. Find service
        const service = await this.prisma.service.findUnique({
            where: { id: serviceId, supplierId: supplier.id },
        });
        if (!service) {
            throw new NotFoundException('Service not found');
        }

        // 3. If categoryId is updated, validate category
        if (dto.categoryId) {
            const category = await this.prisma.category.findUnique({
                where: { id: dto.categoryId },
            });
            if (!category) {
                throw new NotFoundException('Category not found');
            }
            if (!category.parentCategoryId) {
                throw new BadRequestException(
                    'Services must be assigned to a subcategory, not a main category',
                );
            }
            if (category.usedFor !== 'SERVICE') {
                throw new BadRequestException(
                    'This category is not valid for services',
                );
            }
        }

        // 4. Update service
        const updatedService = await this.prisma.service.update({
            where: { id: service.id },
            data: dto,
        });

        // 5. Query back with relations
        const fullService = await this.prisma.service.findUnique({
            where: { id: updatedService.id },
            include: {
                supplier: { include: { user: true } },
                category: true,
            },
        });

        return this.toServiceResponseDto(fullService!);
    }

    async updateServiceImages(
        userId: string,
        serviceId: string,
        file: Express.Multer.File,
    ) {
        // 1. Check supplier
        const supplier = await this.prisma.supplier.findUnique({
            where: { userId },
        });
        if (!supplier) {
            throw new NotFoundException('Supplier not found');
        }

        // 2. Find service
        const service = await this.prisma.service.findUnique({
            where: { id: serviceId, supplierId: supplier.id, isDeleted: false },
        });
        if (!service) {
            throw new NotFoundException('Service not found');
        }

        // 3. Validate image count (max 3)
        if (service.imagesFilesNames.length >= 3) {
            throw new BadRequestException(
                'A maximum of 3 service images is allowed',
            );
        }

        // 4. Upload new image
        const uploadedFileName = await this.fileService.uploadFile(file);

        // 5. Update service images
        const updatedService = await this.prisma.service.update({
            where: { id: service.id },
            data: {
                imagesFilesNames: [
                    ...service.imagesFilesNames,
                    uploadedFileName,
                ],
            },
        });

        // 6. Return DTO
        const fullService = await this.prisma.service.findUnique({
            where: { id: updatedService.id },
            include: {
                supplier: { include: { user: true } },
                category: true,
            },
        });

        return this.toServiceResponseDto(fullService!);
    }

    async deleteServiceImage(
        userId: string,
        serviceId: string,
        fileName: string,
    ) {
        // 1. Check supplier
        const supplier = await this.prisma.supplier.findUnique({
            where: { userId },
        });
        if (!supplier) {
            throw new NotFoundException('Supplier not found.');
        }

        // 2. Find the service
        const service = await this.prisma.service.findUnique({
            where: { id: serviceId, supplierId: supplier.id },
        });
        if (!service) {
            throw new NotFoundException('Service not found.');
        }

        // 3. Check if the image exists in service.imagesFilesNames
        if (!service.imagesFilesNames.includes(fileName)) {
            throw new BadRequestException('Image not found in this service.');
        }

        // 4. Filter out the image
        const updatedImages = service.imagesFilesNames.filter(
            (img) => img !== fileName,
        );

        if (updatedImages.length === 0) {
            throw new BadRequestException(
                'A service must have at least one image.',
            );
        }

        // 5. Update service
        const updatedService = await this.prisma.service.update({
            where: { id: service.id },
            data: { imagesFilesNames: updatedImages },
        });

        // Future Work ?: Delete the file from R2 storage
        // 6. Query back full service with relations for DTO
        const fullService = await this.prisma.service.findUnique({
            where: { id: updatedService.id },
            include: {
                supplier: { include: { user: true } },
                category: true,
            },
        });

        return this.toServiceResponseDto(fullService!);
    }

    async deleteService(userId: string, serviceId: string) {
        // 1. Check supplier
        const supplier = await this.prisma.supplier.findFirst({
            where: { userId },
        });
        if (!supplier) {
            throw new NotFoundException('Supplier not found');
        }

        // 2. Find the service
        const service = await this.prisma.service.findFirst({
            where: { id: serviceId, supplierId: supplier.id, isDeleted: false },
        });
        if (!service) {
            throw new NotFoundException('Service not found');
        }

        // 3. Soft-delete
        await this.prisma.service.update({
            where: { id: service.id },
            data: {
                isDeleted: true,
                deletedAt: new Date(),
            },
        });

        // 4. Return message
        return {
            message: 'Service deleted successfully',
        };
    }
}
