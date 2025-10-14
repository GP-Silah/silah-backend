import {
    Controller,
    Get,
    Post,
    Body,
    Patch,
    Param,
    Req,
    UseGuards,
} from '@nestjs/common';
import { ChatService } from './chat.service';
import { ApiTags } from '@nestjs/swagger';
import { Request } from 'express';
import { ApiDocsJwtAuthGuard } from 'src/auth/decorators/jwt-auth-guard.docs';
import { ApiDocsVerifiedGuard } from 'src/auth/decorators/verified-guard.docs';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { VerifiedGuard } from 'src/auth/guards/verified.guard';
import { UploadImageDto } from './dtos/uploadImage.dto';
import { MarkMessageAsReadDto } from './dtos/markMessageAsRead.dto';

@ApiTags('Chats')
@Controller('chats')
export class ChatController {
    constructor(private readonly chatService: ChatService) {}

    @ApiDocsJwtAuthGuard()
    @ApiDocsVerifiedGuard()
    @UseGuards(JwtAuthGuard, VerifiedGuard)
    @Get('me')
    async getAllChats(@Req() req: Request) {}

    @ApiDocsJwtAuthGuard()
    @ApiDocsVerifiedGuard()
    @UseGuards(JwtAuthGuard, VerifiedGuard)
    @Get('me/:id/messages')
    async getMessagesByChatId(
        @Req() req: Request,
        @Param('id') chatId: string,
    ) {}

    @ApiDocsJwtAuthGuard()
    @ApiDocsVerifiedGuard()
    @UseGuards(JwtAuthGuard, VerifiedGuard)
    @Patch('me/:id/read') // handles single and bulk? or should single message has its own endpoint? which is easier for frontend?
    async markMessageAsRead(
        @Req() req: Request,
        @Param('id') chatId: string,
        @Body() dto: MarkMessageAsReadDto,
    ) {}

    @ApiDocsJwtAuthGuard()
    @ApiDocsVerifiedGuard()
    @UseGuards(JwtAuthGuard, VerifiedGuard)
    @Post('me/:id/upload')
    async sendImage(
        @Req() req: Request,
        @Param('id') chatId: string,
        @Body() dto: UploadImageDto,
    ) {}

    // startChat endpoint?
}
