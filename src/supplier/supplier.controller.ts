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

@ApiTags('Suppliers')
@Controller('suppliers')
export class SupplierController {
    constructor(private readonly supplierService: SupplierService) {}

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
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
    async updateSupplierStoreData(@Req() req: Request) {
        const userId = req.tokenData!.sub;
        return this.supplierService.getSupplierStoreData(userId);
    }

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Patch('me')
    async updateSupplierData() {} //TODO

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Get('me/favorite-categories')
    async getFavoriteCategories(@Req() req: Request) {
        const userId = req.tokenData!.sub;
        return this.supplierService.getSupplierFavoriteCategories(userId);
    }

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Patch('me/favorite-categories')
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
    async getSupplierPlan() {}

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Post('me/subscripe-premium')
    async subscripePremium() {}

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Post('me/start-free-trial')
    async startFreeTrial(@Req() req) {}

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Post('me/store-banner')
    @UseInterceptors(FileInterceptor('file')) // "file" = form field name
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
    async deleteStoreBanner(@Req() req: Request) {
        const userId = req.tokenData!.sub;
        return this.supplierService.deleteStoreBanner(userId);
    }

    @Get(':id/store-banner')
    async getStoreBanner(@Param('id') id: string) {
        return this.supplierService.getStoreBanner(id);
    }

    @Get()
    async getAllSuppliers(
        @Query('status') status?: 'active' | 'inactive',
        @Query('subscription') subscription?: 'subscribed' | 'unsubscribed',
    ) {} //TODO

    @Get(':id')
    async getSupplierDataById(@Param('id') id: string) {
        return this.supplierService.getSupplierDataById(id);
    }

    @Get(':id/store')
    async getSupplierStoreDataById(@Param('id') id: string) {
        return this.supplierService.getSupplierStoreDataById(id);
    }
}
