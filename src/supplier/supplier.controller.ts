import {
    Body,
    Controller,
    Get,
    Patch,
    Post,
    Query,
    Req,
    UseGuards,
} from '@nestjs/common';
import { SupplierService } from './supplier.service';
import { ApiTags } from '@nestjs/swagger';
import { ApiJwtAuthGuard } from 'src/auth/decorators/api-jwt-auth-guard.docs';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { UserRole } from 'src/enums/userRole.enum';
import { Request } from 'express';

@ApiTags('Suppliers')
@Controller('suppliers')
export class SupplierController {
    constructor(private readonly supplierService: SupplierService) {}

    @ApiJwtAuthGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Get('me')
    async getSupplierData() {}

    @Get('me/store')
    async updateSupplierStoreData() {}

    @ApiJwtAuthGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Patch('me')
    async updateSupplierData() {}

    @ApiJwtAuthGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Get('me/favorite-caregories')
    async getFavoriteCategories(@Req() req: Request) {}

    @ApiJwtAuthGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Patch('me/favorite-caregories')
    async toggleFavoriteCategory(
        @Req() req: Request,
        @Body('categoryId') categoryId: number, // or name?
    ) {}

    @ApiJwtAuthGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Get('me/plan')
    async getSupplierPlan() {}

    @ApiJwtAuthGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Post('me/subscripe-premium')
    async subscripePremium() {}

    @ApiJwtAuthGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Post('me/start-free-trial')
    async startFreeTrial(@Req() req) {}

    @Get()
    async getAllSuppliers(
        @Query('status') status?: 'active' | 'inactive',
        @Query('subscription') subscription?: 'subscribed' | 'unsubscribed',
    ) {}

    @Get(':id')
    async getSupplierDataById() {}
}
