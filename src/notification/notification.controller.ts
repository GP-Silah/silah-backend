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
    Res,
} from '@nestjs/common';
import { NotificationService } from './notification.service';
import { ApiTags } from '@nestjs/swagger';
import { ApiDocsJwtAuthGuard } from 'src/auth/decorators/jwt-auth-guard.docs';
import { ApiDocsVerifiedGuard } from 'src/auth/decorators/verified-guard.docs';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { VerifiedGuard } from 'src/auth/guards/verified.guard';
import { Request, Response } from 'express';
import { MarkAsReadDto } from './dtos/markReadBulk.dto';
import { UpdateNotificationPreferencesDto } from './dtos/updateNotificationPreference.dto';
import { Observable, Subject } from 'rxjs';
import { takeUntil, filter, map, tap } from 'rxjs/operators';
import {
    ApiDocsGetMyNotifications,
    ApiDocsGetNotificationPreferences,
    ApiDocsMarkNotificationAsRead,
    ApiDocsMarkNotificationsAsReadInBulk,
    ApiDocsNotificationStream,
    ApiDocsUpdateNotificationPreferences,
} from './notification.docs';
@ApiTags('Notifications')
@Controller('notifications')
export class NotificationController {
    constructor(private readonly notificationService: NotificationService) {}

    @ApiDocsJwtAuthGuard()
    @ApiDocsVerifiedGuard()
    @UseGuards(JwtAuthGuard, VerifiedGuard)
    @Get('me/preferences')
    @ApiDocsGetNotificationPreferences()
    async getNotificationPreferences(@Req() req: Request) {
        const userId = req.tokenData!.sub;
        return this.notificationService.getNotificationPreferences(userId);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsVerifiedGuard()
    @UseGuards(JwtAuthGuard, VerifiedGuard)
    @Patch('me/preferences')
    @ApiDocsUpdateNotificationPreferences()
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
    @ApiDocsGetMyNotifications()
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
    @ApiDocsMarkNotificationAsRead()
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
    @ApiDocsMarkNotificationsAsReadInBulk()
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
    @ApiDocsNotificationStream()
    @Get('stream')
    @Sse('stream')
    notificationStream(
        @Req() req: Request,
        @Res({ passthrough: true }) res: Response,
    ): Observable<MessageEvent> {
        const frontendUrl = process.env.FRONTEND_URL ?? 'http://localhost:5173';
        // Set SSE + CORS headers
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        res.setHeader('Access-Control-Allow-Origin', frontendUrl); // exact frontend URL
        res.setHeader('Access-Control-Allow-Credentials', 'true'); // important for cookies

        const userId = req.tokenData!.sub;

        const disconnect$ = new Subject<void>(); // This will signal when to stop
        // When the browser or client disconnects:
        req.on('close', () => {
            disconnect$.next(); // trigger the stop
            disconnect$.complete();
        });

        return this.notificationService.getNotificationStream().pipe(
            // tap((event) =>
            //     console.log('📡 Stream event:', event.receiverUserId),
            // ), // add tap from rxjs/operators
            filter((event) => event.receiverUserId === userId),
            takeUntil(disconnect$), // Stop streaming when disconnect$ emits
            map((event) => {
                const payload = JSON.stringify(event.notification);
                return { data: payload }; // must be stringified
            }),
        );
    }
}
