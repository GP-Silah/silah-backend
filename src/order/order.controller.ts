import {
    BadRequestException,
    Body,
    Controller,
    Get,
    Param,
    Patch,
    Req,
    UseGuards,
} from '@nestjs/common';
import { OrderService } from './order.service';
import { ApiTags } from '@nestjs/swagger';
import { Request } from 'express';
import { ApiJwtAuthGuard } from 'src/auth/decorators/api-jwt-auth-guard.docs';
import { ApiRolesGuard } from 'src/auth/decorators/api-roles-guard.docs';
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

@ApiTags('Orders')
@Controller('orders')
export class OrderController {
    constructor(private readonly orderService: OrderService) {}

    @ApiJwtAuthGuard()
    @UseGuards(JwtAuthGuard)
    @Get('me')
    @ApiDocsGetMyOrders()
    async getMyOrders(@Req() req: Request) {
        const userId = req.tokenData!.sub;
        return this.orderService.getMyOrders(userId);
    }

    @ApiJwtAuthGuard()
    @UseGuards(JwtAuthGuard)
    @Get(':orderId')
    @ApiDocsGetOrderById()
    async getOrderById(@Req() req: Request, @Param('orderId') orderId: string) {
        const userId = req.tokenData!.sub;
        return this.orderService.getOrderById(userId, orderId);
    }

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
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

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard)
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
