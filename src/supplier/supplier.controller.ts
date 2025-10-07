import {
    Body,
    Controller,
    Delete,
    FileTypeValidator,
    Get,
    MaxFileSizeValidator,
    Param,
    ParseFilePipe,
    Patch,
    Post,
    Query,
    Req,
    UploadedFile,
    UseGuards,
    UseInterceptors,
} from '@nestjs/common';
import { SupplierService } from './supplier.service';
import { ApiTags } from '@nestjs/swagger';
import { ApiJwtAuthGuard } from 'src/auth/decorators/api-jwt-auth-guard.docs';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { UserRole } from 'src/enums/userRole.enum';
import { Request } from 'express';
import { FileInterceptor } from '@nestjs/platform-express';
import { ApiRolesGuard } from 'src/auth/decorators/api-roles-guard.docs';
import { SupplierResponseDto } from './dtos/supplierResponse.dto';
import {
    ApiDocsDeleteStoreBanner,
    ApiDocsGetAllSuppliers,
    ApiDocsGetFavoriteCategories,
    ApiDocsGetMySupplierData,
    ApiDocsGetStockLevels,
    ApiDocsGetStoreBanner,
    ApiDocsGetSupplierDataById,
    ApiDocsGetSupplierPlan,
    ApiDocsGetSupplierStoreDataById,
    ApiDocsStartFreeTrial,
    ApiDocsSubscribePremium,
    ApiDocsToggleFavoriteCategory,
    ApiDocsUpdateMySupplierData,
    ApiDocsUpdateStoreBanner,
} from './supplier.docs';
import { InactiveSupplierResponseDto } from './dtos/inactiveSupplierResponse.dto';

@ApiTags('Suppliers')
@Controller('suppliers')
export class SupplierController {
    constructor(private readonly supplierService: SupplierService) {}

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @ApiDocsGetMySupplierData()
    @Get('me')
    async getSupplierData(@Req() req: Request) {
        const userId = req.tokenData!.sub;
        return this.supplierService.getSupplierData(userId);
    }

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Get('me/store')
    @ApiDocsGetMySupplierData()
    async updateSupplierStoreData(@Req() req: Request) {
        const userId = req.tokenData!.sub;
        return this.supplierService.getSupplierStoreData(userId);
    }

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Get('me/stock-levels')
    @ApiDocsGetStockLevels()
    async getStockLevels(@Req() req: Request) {
        const userId = req.tokenData!.sub;
        return this.supplierService.getStockLevels(userId);
    }

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Patch('me')
    @ApiDocsUpdateMySupplierData()
    async updateSupplierData(@Req() req: Request) {
        const userId = req.tokenData!.sub;
        return this.supplierService.updateSupplierData(userId, req.body);
    }

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Get('me/favorite-categories')
    @ApiDocsGetFavoriteCategories()
    async getFavoriteCategories(@Req() req: Request) {
        const userId = req.tokenData!.sub;
        return this.supplierService.getSupplierFavoriteCategories(userId);
    }

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Patch('me/favorite-categories')
    @ApiDocsToggleFavoriteCategory()
    async toggleFavoriteCategory(
        @Req() req: Request,
        @Body('categoryId') categoryId: number,
    ) {
        const userId = req.tokenData!.sub;
        return this.supplierService.toggleFavoriteCategory(userId, categoryId);
    }

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Get('me/plan')
    @ApiDocsGetSupplierPlan()
    async getSupplierPlan(@Req() req: Request) {
        const userId = req.tokenData!.sub;
        return this.supplierService.getSupplierPlan(userId);
    }

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Post('me/subscripe-premium')
    @ApiDocsSubscribePremium()
    async subscripePremium(@Req() req: Request) {
        const userId = req.tokenData!.sub;
        return this.supplierService.subscripePremium(userId);
    }

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Post('me/start-free-trail')
    @ApiDocsStartFreeTrial()
    async startFreeTrial(@Req() req) {
        const userId = req.tokenData!.sub;
        return this.supplierService.startFreeTrial(userId);
    }

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Post('me/store-banner')
    @UseInterceptors(FileInterceptor('file')) // "file" = form field name
    @ApiDocsUpdateStoreBanner()
    async updateStoreBanner(
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
        @Req() req: Request,
    ) {
        const userId = req.tokenData!.sub;
        return this.supplierService.updateStoreBanner(file, userId);
    }

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Delete('me/store-banner')
    @ApiDocsDeleteStoreBanner()
    async deleteStoreBanner(@Req() req: Request) {
        const userId = req.tokenData!.sub;
        return this.supplierService.deleteStoreBanner(userId);
    }

    @ApiDocsGetStoreBanner()
    @Get(':id/store-banner')
    async getStoreBanner(@Param('id') id: string) {
        return this.supplierService.getStoreBanner(id);
    }

    @ApiDocsGetAllSuppliers()
    @Get()
    async getAllSuppliers(
        @Query('status') status?: 'active' | 'inactive',
        @Query('subscription') subscription?: 'subscribed' | 'unsubscribed',
    ): Promise<(SupplierResponseDto | InactiveSupplierResponseDto)[]> {
        return this.supplierService.getAllSuppliers(status, subscription);
    }

    @ApiDocsGetSupplierDataById()
    @Get(':id')
    async getSupplierDataById(@Param('id') id: string) {
        return this.supplierService.getSupplierDataById(id);
    }

    @ApiDocsGetSupplierStoreDataById()
    @Get(':id/store')
    async getSupplierStoreDataById(@Param('id') id: string) {
        return this.supplierService.getSupplierStoreDataById(id);
    }
}
