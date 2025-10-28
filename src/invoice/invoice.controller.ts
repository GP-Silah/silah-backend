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
import { ApiTags } from '@nestjs/swagger';
import { Request } from 'express';
import { ApiDocsJwtAuthGuard } from 'src/auth/decorators/jwt-auth-guard.docs';
import { ApiDocsRolesGuard } from 'src/auth/decorators/roles-guard.docs';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { UserRole } from 'src/enums/userRole.enum';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { InvoiceStatus } from '@prisma/client';
import { CreateInvoiceDto } from './dtos/createInvoice.dto';
import {
    ApiDocsCreateInvoice,
    ApiDocsGetMyInvoiceById,
    ApiDocsGetMyInvoices,
    ApiDocsPayInvoice,
    ApiDocsUpdateInvoiceStatus,
} from './invoice.docs';
import { ApiDocsVerifiedGuard } from 'src/auth/decorators/verified-guard.docs';
import { VerifiedGuard } from 'src/auth/guards/verified.guard';
import { PayInvoiceDto } from './dtos/payInvoice.dto';

@ApiTags('Invoices')
@Controller('invoices')
export class InvoiceController {
    constructor(private readonly invoiceService: InvoiceService) {}

    @ApiDocsJwtAuthGuard()
    @UseGuards(JwtAuthGuard)
    @Get('me')
    @ApiDocsGetMyInvoices()
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

    @ApiDocsJwtAuthGuard()
    @UseGuards(JwtAuthGuard)
    @Get('me/:id')
    @ApiDocsGetMyInvoiceById()
    async getMyInvoiceById(@Req() req: Request, @Param('id') id: string) {
        const userId = req.tokenData!.sub;
        return this.invoiceService.getMyInvoiceById(userId, id);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @Post()
    @ApiDocsCreateInvoice()
    async createInvoice(@Body() dto: CreateInvoiceDto) {
        return this.invoiceService.createInvoice(dto);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @Patch('me/:id/status')
    @ApiDocsUpdateInvoiceStatus()
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

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @Post('me/:id/pay')
    @ApiDocsPayInvoice()
    async payInvoice(
        @Req() req: Request,
        @Param('id') id: string,
        @Body() dto?: PayInvoiceDto,
    ) {
        const userId = req.tokenData!.sub;
        return this.invoiceService.payInvoice(userId, id, dto);
    }
}
