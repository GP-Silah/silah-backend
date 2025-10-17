import {
    BadRequestException,
    Body,
    Controller,
    Get,
    Param,
    Patch,
    Query,
    Req,
    UseGuards,
    Headers,
} from '@nestjs/common';
import { OrderService } from './order.service';
import { ApiTags } from '@nestjs/swagger';
import { Request } from 'express';
import { ApiDocsJwtAuthGuard } from 'src/auth/decorators/jwt-auth-guard.docs';
import { ApiDocsRolesGuard } from 'src/auth/decorators/roles-guard.docs';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { UserRole } from 'src/enums/userRole.enum';
import { OrderStatus } from '@prisma/client';
import {
    ApiDocsConfirmDelivery,
    ApiDocsGetMyOrders,
    ApiDocsGetOrderById,
    ApiDocsUpdateOrderStatus,
} from './order.docs';
import { ApiDocsVerifiedGuard } from 'src/auth/decorators/verified-guard.docs';
import { VerifiedGuard } from 'src/auth/guards/verified.guard';

@ApiTags('Orders')
@Controller('orders')
export class OrderController {
    constructor(private readonly orderService: OrderService) {}

    /** Helper function to determine target language */
    private async resolveTargetLang(
        req: Request,
        lang?: 'ar' | 'en',
        langHeader?: 'ar' | 'en',
    ) {
        let targetLang: 'ar' | 'en' = 'en';

        // Priority: query param > header > user preference > default
        if (lang) {
            targetLang = lang;
        } else if (langHeader) {
            targetLang = langHeader;
        } else if (req.tokenData?.sub) {
            const user = await this.orderService.getUserLanguage(
                req.tokenData.sub,
            );
            if (user) targetLang = user;
        }

        return targetLang;
    }

    @ApiDocsJwtAuthGuard()
    @UseGuards(JwtAuthGuard)
    @Get('me')
    @ApiDocsGetMyOrders()
    async getMyOrders(
        @Req() req: Request,
        @Query('status') status?: string,
        @Headers('accept-language') langHeader?: 'ar' | 'en',
        @Query('lang') lang?: 'ar' | 'en',
    ) {
        if (status) {
            const normalized = status.toUpperCase();
            const validStatuses = Object.values(OrderStatus);
            if (!validStatuses.includes(normalized as OrderStatus)) {
                throw new BadRequestException(
                    `Invalid order status: ${status}`,
                );
            }
            status = normalized as OrderStatus;
        }
        const userId = req.tokenData!.sub;
        const targetLang = await this.resolveTargetLang(req, lang, langHeader);
        return this.orderService.getMyOrders(
            userId,
            status as OrderStatus,
            targetLang,
        );
    }

    @ApiDocsJwtAuthGuard()
    @UseGuards(JwtAuthGuard)
    @Get(':orderId')
    @ApiDocsGetOrderById()
    async getOrderById(
        @Req() req: Request,
        @Param('orderId') orderId: string,
        @Headers('accept-language') langHeader?: 'ar' | 'en',
        @Query('lang') lang?: 'ar' | 'en',
    ) {
        const userId = req.tokenData!.sub;
        const targetLang = await this.resolveTargetLang(req, lang, langHeader);
        return this.orderService.getOrderById(userId, orderId, targetLang);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @Patch(':orderId/status')
    @ApiDocsUpdateOrderStatus()
    async updateOrderStatus(
        @Req() req: Request,
        @Param('orderId') orderId: string,
        @Body('newStatus') newStatus: string | OrderStatus,
    ) {
        // Get all enum values except COMPLETED (suppliers cannot set status to COMPLETED)
        const allowedStatuses = Object.values(OrderStatus).filter(
            (status) => status !== OrderStatus.COMPLETED,
        ) as OrderStatus[];
        // Validate that newStatus is a valid OrderStatus
        if (!allowedStatuses.includes(newStatus as OrderStatus)) {
            throw new BadRequestException(
                `Invalid order status. Valid statuses: ${allowedStatuses.join(', ')}`,
            );
        }
        const validNewStatus: OrderStatus = newStatus as OrderStatus; // At this point, newStatus is guaranteed to be valid
        const userId = req.tokenData!.sub;
        return this.orderService.updateOrderStatus(
            userId,
            orderId,
            validNewStatus,
        );
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @Patch(':orderId/confirm-delivery')
    @ApiDocsConfirmDelivery()
    async confirmDelivery(
        @Req() req: Request,
        @Param('orderId') orderId: string,
    ) {
        const userId = req.tokenData!.sub;
        return this.orderService.confirmDelivery(userId, orderId);
    }
}
