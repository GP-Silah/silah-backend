import {
    BadRequestException,
    Body,
    Controller,
    Delete,
    FileTypeValidator,
    Get,
    Headers,
    MaxFileSizeValidator,
    Param,
    ParseFilePipe,
    Patch,
    Post,
    Query,
    Req,
    UploadedFile,
    UploadedFiles,
    UseGuards,
    UseInterceptors,
} from '@nestjs/common';
import { ServiceService } from './service.service';
import { ApiTags } from '@nestjs/swagger';
import { ApiDocsJwtAuthGuard } from 'src/auth/decorators/jwt-auth-guard.docs';
import { ApiDocsRolesGuard } from 'src/auth/decorators/roles-guard.docs';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { UserRole } from 'src/enums/userRole.enum';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { FileInterceptor, FilesInterceptor } from '@nestjs/platform-express';
import { Request } from 'express';
import { CreateServiceDto } from './dtos/createService.dto';
import { UpdateServiceDto } from './dtos/updateService.dto';
import {
    ApiDocsCreateService,
    ApiDocsDeleteService,
    ApiDocsDeleteServiceImage,
    ApiDocsDuplicateService,
    ApiDocsFakeGetCreateServiceDto,
    ApiDocsGetAllServices,
    ApiDocsGetAllSupplierServices,
    ApiDocsGetServiceById,
    ApiDocsUpdateService,
    ApiDocsUpdateServiceImage,
} from './service.docs';
import { ApiDocsVerifiedGuard } from 'src/auth/decorators/verified-guard.docs';
import { VerifiedGuard } from 'src/auth/guards/verified.guard';

@ApiTags('Services')
@Controller('services')
export class ServiceController {
    constructor(private readonly serviceService: ServiceService) {}

    @Get()
    @ApiDocsGetAllServices()
    async getAllServices(
        @Req() req: Request,
        @Headers('accept-language') langHeader?: 'ar' | 'en',
        @Query('lang') lang?: 'ar' | 'en',
    ) {
        const userId = req.tokenData?.sub;
        const finalLang = lang || langHeader || 'en';
        return this.serviceService.getAllServices(finalLang, userId);
    }

    @Get(':serviceId')
    @ApiDocsGetServiceById()
    async getServiceById(
        @Param('serviceId') serviceId: string,
        @Req() req: Request,
        @Headers('accept-language') langHeader?: 'ar' | 'en',
        @Query('lang') lang?: 'ar' | 'en',
    ) {
        const userId = req.tokenData?.sub;
        const finalLang = lang || langHeader || 'en';
        return this.serviceService.getServiceById(serviceId, finalLang, userId);
    }

    @Get('supplier/:supplierId')
    @ApiDocsGetAllSupplierServices()
    async getAllSupplierServices(
        @Param('souplierId') supplierId: string,
        @Req() req: Request,
        @Headers('accept-language') langHeader?: 'ar' | 'en',
        @Query('lang') lang?: 'ar' | 'en',
    ) {
        const userId = req.tokenData?.sub;
        const finalLang = lang || langHeader || 'en';
        return this.serviceService.getAllSupplierServices(
            supplierId,
            finalLang,
            userId,
        );
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @Post()
    @UseInterceptors(FilesInterceptor('files', 3)) // note: "files" for multiple files
    @ApiDocsCreateService()
    async createService(
        @UploadedFiles(
            new ParseFilePipe({
                validators: [
                    new MaxFileSizeValidator({ maxSize: 5 * 1024 * 1024 }),
                    new FileTypeValidator({
                        fileType: /^image\/(png|jpe?g|webp)$/i,
                        skipMagicNumbersValidation: true,
                    }),
                ],
            }),
        )
        files: Express.Multer.File[],
        @Req() req: Request,
        // @Body('dto', ParseJsonPipe) dto: CreateServiceDto,
    ) {
        // Parse the dto from req.body manually (because NestJS way throws errors and workarounds failed)
        let dto: CreateServiceDto;
        try {
            dto = JSON.parse(req.body.dto);
        } catch (err) {
            throw new BadRequestException('Invalid JSON in form field');
        }
        const userId = req.tokenData!.sub;
        return this.serviceService.createService(userId, dto, files);
    }
    @Get('create-service-dto')
    @ApiDocsFakeGetCreateServiceDto()
    dummy() {
        return; // Never called
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @Post(':serviceId/clone')
    @ApiDocsDuplicateService()
    async duplicateService(
        @Param('serviceId') serviceId: string,
        @Req() req: Request,
    ) {
        const userId = req.tokenData!.sub;
        return this.serviceService.duplicateService(userId, serviceId);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @Patch(':serviceId')
    @ApiDocsUpdateService()
    async updateService(
        @Param('serviceId') serviceId: string,
        @Req() req: Request,
        @Body() dto: UpdateServiceDto,
    ) {
        const userId = req.tokenData!.sub;
        return this.serviceService.updateService(userId, serviceId, dto);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @UseInterceptors(FileInterceptor('file'))
    @Patch(':serviceId/images')
    @ApiDocsUpdateServiceImage()
    async updateServiceImages(
        @UploadedFile(
            new ParseFilePipe({
                validators: [
                    new MaxFileSizeValidator({ maxSize: 5 * 1024 * 1024 }),
                    new FileTypeValidator({
                        fileType: /^image\/(png|jpe?g|webp)$/i,
                        skipMagicNumbersValidation: true,
                    }),
                ],
            }),
        )
        file: Express.Multer.File,
        @Param('serviceId') serviceId: string,
        @Req() req: Request,
    ) {
        const userId = req.tokenData!.sub;
        return this.serviceService.updateServiceImages(userId, serviceId, file);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @Delete(':serviceId/image/:fileName')
    @ApiDocsDeleteServiceImage()
    async deleteServiceImage(
        @Param('serviceId') serviceId: string,
        @Param('fileName') fileName: string,
        @Req() req: Request,
    ) {
        const userId = req.tokenData!.sub;
        return this.serviceService.deleteServiceImage(
            userId,
            serviceId,
            fileName,
        );
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @Delete(':serviceId')
    @ApiDocsDeleteService()
    async deleteService(
        @Param('serviceId') serviceId: string,
        @Req() req: Request,
    ) {
        const userId = req.tokenData!.sub;
        return this.serviceService.deleteService(userId, serviceId);
    }
}
