import {
    BadRequestException,
    Controller,
    Get,
    Param,
    Post,
    Query,
    Req,
    UseGuards,
} from '@nestjs/common';
import { GroupPurchaseService } from './group-purchase.service';
import { ApiTags } from '@nestjs/swagger';
import { Request } from 'express';
import { ApiDocsJwtAuthGuard } from 'src/auth/decorators/jwt-auth-guard.docs';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { ApiDocsRolesGuard } from 'src/auth/decorators/roles-guard.docs';
import { ApiDocsVerifiedGuard } from 'src/auth/decorators/verified-guard.docs';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { UserRole } from 'src/enums/userRole.enum';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { VerifiedGuard } from 'src/auth/guards/verified.guard';
import {
    ApiDocsGetAllGroupPurchaseForProduct,
    ApiDocsGetGroupById,
    ApiDocsGetSuitableGroupPurchasesForProduct,
    ApiDocsJoinGroupPurchase,
    ApiDocsStartGroupPurchase,
} from './group-purchase.docs';

@ApiTags('Group Purchases')
@Controller('group-purchases')
export class GroupPurchaseController {
    constructor(private readonly groupPurchaseService: GroupPurchaseService) {}

    @Get('products/:id')
    @ApiDocsGetAllGroupPurchaseForProduct()
    async getAllGroupPurchaseForProduct(@Param('id') productId: string) {
        return this.groupPurchaseService.getAllGroupPurchaseForProduct(
            productId,
        );
    }

    @Get(':id')
    @ApiDocsGetGroupById()
    async getGroupById(@Param('id') groupId: string) {
        return this.groupPurchaseService.getGroupById(groupId);
    }

    @ApiDocsJwtAuthGuard()
    @UseGuards(JwtAuthGuard)
    @Get('products/:id/suitable-groups')
    @ApiDocsGetSuitableGroupPurchasesForProduct()
    async getSuitableGroupPurchasesForProduct(
        @Req() req: Request,
        @Param('id') productId: string,
    ) {
        const userId = req.tokenData!.sub;
        return this.groupPurchaseService.getSuitableGroupPurchasesForProduct(
            userId,
            productId,
        );
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @Post('products/:id/start')
    @ApiDocsStartGroupPurchase()
    async startGroupPurchase(
        @Req() req: Request,
        @Param('id') productId: string,
        @Query('quantity') quantity: string,
    ) {
        // Convert query param safely
        const validQuantity =
            quantity && Number(quantity) > 0 ? Number(quantity) : undefined;
        if (!validQuantity) {
            throw new BadRequestException(
                `Quantity must exist and be greater than zero, found: ${quantity}`,
            );
        }
        const userId = req.tokenData!.sub;
        return this.groupPurchaseService.startGroupPurchase(
            userId,
            productId,
            validQuantity,
        );
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @Post('groups/:id/join')
    @ApiDocsJoinGroupPurchase()
    async joinGroupPurchase(
        @Req() req: Request,
        @Param('id') groupId: string,
        @Query('quantity') quantity: string,
    ) {
        // Convert query param safely
        const validQuantity =
            quantity && Number(quantity) > 0 ? Number(quantity) : undefined;
        if (!validQuantity) {
            throw new BadRequestException(
                `Quantity must exist and be greater than zero, found: ${quantity}`,
            );
        }
        const userId = req.tokenData!.sub;
        return this.groupPurchaseService.joinGroupPurchase(
            userId,
            groupId,
            validQuantity,
        );
    }
}
