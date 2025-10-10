import {
    BadRequestException,
    Body,
    Controller,
    Get,
    Param,
    Patch,
    Post,
    Query,
    Req,
    UseGuards,
} from '@nestjs/common';
import { InvoiceService } from './invoice.service';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { Request } from 'express';
import { ApiJwtAuthGuard } from 'src/auth/decorators/api-jwt-auth-guard.docs';
import { ApiRolesGuard } from 'src/auth/decorators/api-roles-guard.docs';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { UserRole } from 'src/enums/userRole.enum';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { InvoiceStatus } from '@prisma/client';
import { CreateInvoiceDto } from './dtos/createInvoice.dto';

@ApiTags('Invoices')
@Controller('invoices')
export class InvoiceController {
    constructor(private readonly invoiceService: InvoiceService) {}

    @ApiJwtAuthGuard()
    @UseGuards(JwtAuthGuard)
    @Get('me')
    async getMyInvoices(
        @Req() req: Request,
        @Query('status') status?: string,
        @Query('showFor') showFor?: string,
    ) {
        if (status) {
            const normalized = status.toUpperCase();
            const validStatuses = Object.values(InvoiceStatus);
            if (!validStatuses.includes(normalized as InvoiceStatus)) {
                throw new BadRequestException(
                    `Invalid invoice status: ${status}`,
                );
            }
            status = normalized as InvoiceStatus;
        }
        if (showFor) {
            const acceptedValues = [
                'all',
                'products',
                'services',
                'bids',
                'groups',
            ];
            if (!acceptedValues.includes(showFor)) {
                throw new BadRequestException(
                    `Invalid showFor choice: ${showFor}`,
                );
            }
        }
        const userId = req.tokenData!.sub;
        return this.invoiceService.getMyInvoices(
            userId,
            status as InvoiceStatus,
            showFor,
        );
    }

    @ApiJwtAuthGuard()
    @UseGuards(JwtAuthGuard)
    @Get('me/:id')
    async getMyInvoiceById(@Req() req: Request, @Param('id') id: string) {
        const userId = req.tokenData!.sub;
        return this.invoiceService.getMyInvoiceById(userId, id);
    }

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Post()
    async createInvoice(@Body() dto: CreateInvoiceDto) {
        return this.invoiceService.createInvoice(dto);
    }

    //TODO: when groups are done
    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Post(':groupId')
    @ApiOperation({
        deprecated: true,
        summary: 'Not implemented yet',
        description: 'This endpoint is a placeholder and not implemented yet.',
    })
    async createPreInvoice(
        @Req() req: Request,
        @Param('groupId') groupId: string,
    ) {}

    //TODO: think of offers logic

    //TODO: when groups and offers are finished think about the cron job

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Patch('me/:id/status')
    async updateInvoiceStatus(
        @Req() req: Request,
        @Param('id') id: string,
        @Query('status') status: string,
    ) {
        const newStatus = status.toUpperCase();
        const allowedStatuses = [
            InvoiceStatus.ACCEPTED,
            InvoiceStatus.REJECTED,
        ] as const;
        if (!(allowedStatuses as readonly string[]).includes(newStatus)) {
            throw new BadRequestException(
                `Invalid status. Allowed values: ${allowedStatuses.join(', ')}`,
            );
        }
        const userId = req.tokenData!.sub;
        return this.invoiceService.updateInvoiceStatus(
            userId,
            id,
            newStatus as InvoiceStatus,
        );
    }

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Post('me/:id/pay')
    async payInvoice(@Req() req: Request, @Param('id') id: string) {
        const userId = req.tokenData!.sub;
        return this.invoiceService.payInvoice(userId, id);
    }
}
