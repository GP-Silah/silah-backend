import {
    Body,
    Controller,
    Get,
    Param,
    Patch,
    Query,
    Req,
    Sse,
    UseGuards,
    MessageEvent,
} from '@nestjs/common';
import { NotificationService } from './notification.service';
import { ApiTags } from '@nestjs/swagger';
import { ApiDocsJwtAuthGuard } from 'src/auth/decorators/jwt-auth-guard.docs';
import { ApiDocsVerifiedGuard } from 'src/auth/decorators/verified-guard.docs';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { VerifiedGuard } from 'src/auth/guards/verified.guard';
import { Request } from 'express';
import { MarkAsReadDto } from './dtos/markReadBulk.dto';
import { UpdateNotificationPreferencesDto } from './dtos/updateNotificationPreference.dto';
import { Observable, Subject } from 'rxjs';
import { takeUntil, filter, map } from 'rxjs/operators';
@ApiTags('Notifications')
@Controller('notifications')
export class NotificationController {
    constructor(private readonly notificationService: NotificationService) {}

    @ApiDocsJwtAuthGuard()
    @ApiDocsVerifiedGuard()
    @UseGuards(JwtAuthGuard, VerifiedGuard)
    @Patch('me/preferences')
    async updateNotificationPreferences(
        @Req() req: Request,
        @Body() dto: UpdateNotificationPreferencesDto,
    ) {
        const userId = req.tokenData!.sub;
        return this.notificationService.updateNotificationPreferences(
            userId,
            dto,
        );
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsVerifiedGuard()
    @UseGuards(JwtAuthGuard, VerifiedGuard)
    @Get('me')
    async getMyNotifications(
        @Req() req: Request,
        @Query('date') date?: string,
        @Query('type') type?: string,
    ) {
        const userId = req.tokenData!.sub;
        return this.notificationService.getMyNotifications(userId, date, type);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsVerifiedGuard()
    @UseGuards(JwtAuthGuard, VerifiedGuard)
    @Patch(':id/read')
    async markNotificationAsRead(
        @Req() req: Request,
        @Param('id') notificationId: string,
    ) {
        const userId = req.tokenData!.sub;
        return this.notificationService.markNotificationAsRead(
            userId,
            notificationId,
        );
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsVerifiedGuard()
    @UseGuards(JwtAuthGuard, VerifiedGuard)
    @Patch('read-many')
    async markNotificationsAsReadInBulk(
        @Req() req: Request,
        @Body() dto: MarkAsReadDto,
    ) {
        const userId = req.tokenData!.sub;
        return this.notificationService.markNotificationsAsReadInBulk(
            userId,
            dto,
        );
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsVerifiedGuard()
    @UseGuards(JwtAuthGuard, VerifiedGuard)
    @Get('stream')
    @Sse('stream')
    notificationStream(@Req() req: Request): Observable<MessageEvent> {
        const userId = req.tokenData!.sub;

        const disconnect$ = new Subject<void>(); // This will signal when to stop
        // When the browser or client disconnects:
        req.on('close', () => {
            disconnect$.next(); // trigger the stop
            disconnect$.complete();
        });

        return this.notificationService.getNotificationStream().pipe(
            filter((event) => event.receiverUserId === userId),
            takeUntil(disconnect$), // Stop streaming when disconnect$ emits
            map((event) => ({
                data: event.notification,
                type: 'new-notification',
            })),
        );
    }
}
