import {
    Body,
    Controller,
    Get,
    Param,
    Patch,
    Req,
    Sse,
    UseGuards,
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
import { interval, map, Observable } from 'rxjs';

@ApiTags('Notifications')
@Controller('notification')
export class NotificationController {
    constructor(private readonly notificationService: NotificationService) {}

    @ApiDocsJwtAuthGuard()
    @ApiDocsVerifiedGuard()
    @UseGuards(JwtAuthGuard, VerifiedGuard)
    @Patch('me/preferences')
    async updateNotificationPreferences(
        @Req() req: Request,
        @Body() dto: UpdateNotificationPreferencesDto,
    ) {}

    @ApiDocsJwtAuthGuard()
    @ApiDocsVerifiedGuard()
    @UseGuards(JwtAuthGuard, VerifiedGuard)
    @Get('me')
    async getMyNotifications(@Req() req: Request) {}

    @ApiDocsJwtAuthGuard()
    @ApiDocsVerifiedGuard()
    @UseGuards(JwtAuthGuard, VerifiedGuard)
    @Patch(':id/read')
    async markNotificationAsRead(
        @Req() req: Request,
        @Param('id') notificationId: string,
    ) {}

    @ApiDocsJwtAuthGuard()
    @ApiDocsVerifiedGuard()
    @UseGuards(JwtAuthGuard, VerifiedGuard)
    @Patch('read-many')
    async markNotificationsAsReadInBulk(
        @Req() req: Request,
        @Body() dto: MarkAsReadDto,
    ) {}

    @ApiDocsJwtAuthGuard()
    @ApiDocsVerifiedGuard()
    @UseGuards(JwtAuthGuard, VerifiedGuard)
    @Get('stream')
    @Sse()
    streamNotifications(): Observable<{ data: any; type?: string }> {
        return interval(1000).pipe(
            map(() => ({
                data: { message: 'ping', timestamp: new Date() },
                type: 'ping', // optional, helps frontend distinguish event type
            })),
        );
    }
}
