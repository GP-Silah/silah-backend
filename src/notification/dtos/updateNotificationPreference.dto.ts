import { IsBoolean, IsOptional } from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class UpdateNotificationPreferencesDto {
    @ApiPropertyOptional({
        description: 'Toggle all notifications (applies to all users)',
    })
    @IsOptional()
    @IsBoolean()
    allowNotifications?: boolean;

    @ApiPropertyOptional({
        description: 'Receive notifications for new chat messages (all users)',
    })
    @IsOptional()
    @IsBoolean()
    newMessageNotify?: boolean;

    @ApiPropertyOptional({
        description: 'Receive notifications for new orders (suppliers only)',
    })
    @IsOptional()
    @IsBoolean()
    newOrderNotify?: boolean;

    @ApiPropertyOptional({
        description: 'Receive notifications for new reviews (suppliers only)',
    })
    @IsOptional()
    @IsBoolean()
    newReviewNotify?: boolean;

    @ApiPropertyOptional({
        description: 'Receive notifications for new invoices (buyers only)',
    })
    @IsOptional()
    @IsBoolean()
    newInvoiceNotify?: boolean;

    @ApiPropertyOptional({
        description: 'Receive notifications for new offers (buyers only)',
    })
    @IsOptional()
    @IsBoolean()
    newOfferNotify?: boolean;

    @ApiPropertyOptional({
        description:
            'Receive notifications for bidding status changes (suppliers only)',
    })
    @IsOptional()
    @IsBoolean()
    biddingStatusNotify?: boolean;

    @ApiPropertyOptional({
        description:
            'Receive notifications for invoice status changes (suppliers only)',
    })
    @IsOptional()
    @IsBoolean()
    invoiceStatusNotify?: boolean;

    @ApiPropertyOptional({
        description:
            'Receive notifications for order status changes (buyers only)',
    })
    @IsOptional()
    @IsBoolean()
    orderStatusNotify?: boolean;

    @ApiPropertyOptional({
        description:
            'Receive notifications for group purchase status changes (buyers only)',
    })
    @IsOptional()
    @IsBoolean()
    groupPurchaseStatusNotify?: boolean;
}
