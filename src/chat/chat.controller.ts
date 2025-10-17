import {
    Controller,
    Get,
    Post,
    Body,
    Patch,
    Param,
    Req,
    UseGuards,
    UseInterceptors,
    UploadedFile,
    ParseFilePipe,
    MaxFileSizeValidator,
    FileTypeValidator,
    Query,
} from '@nestjs/common';
import { ChatService } from './chat.service';
import { ApiTags } from '@nestjs/swagger';
import { Request } from 'express';
import { ApiDocsJwtAuthGuard } from 'src/auth/decorators/jwt-auth-guard.docs';
import { ApiDocsVerifiedGuard } from 'src/auth/decorators/verified-guard.docs';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { VerifiedGuard } from 'src/auth/guards/verified.guard';
import { MarkMessageAsReadDto } from './dtos/markMessageAsRead.dto';
import { FileInterceptor } from '@nestjs/platform-express';
import { ChatGateway } from './chat.gateway';
import {
    ApiDocsFakeWebSocketGuide,
    ApiDocsGetAllChats,
    ApiDocsGetMessagesForChat,
    ApiDocsMarkMessagesAsRead,
    ApiDocsSendImageMessage,
} from './chat.docs';

@ApiTags('Chats')
@Controller('chats')
export class ChatController {
    constructor(
        private readonly chatService: ChatService,
        private readonly chatGateway: ChatGateway,
    ) {}

    @ApiDocsJwtAuthGuard()
    @ApiDocsVerifiedGuard()
    @UseGuards(JwtAuthGuard, VerifiedGuard)
    @ApiDocsGetAllChats()
    @Get('me')
    async getAllChats(
        @Req() req: Request,
        @Query('date') date?: 'all' | 'today' | 'this-week' | 'this-month',
        @Query('status') status?: 'all' | 'read' | 'unread',
    ) {
        const userId = req.tokenData!.sub;
        return this.chatService.getAllChats(userId, date, status);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsVerifiedGuard()
    @UseGuards(JwtAuthGuard, VerifiedGuard)
    @Get('me/:id/messages')
    @ApiDocsGetMessagesForChat()
    async getMessagesForChatById(
        @Req() req: Request,
        @Param('id') chatId: string,
    ) {
        const userId = req.tokenData!.sub;
        return this.chatService.getMessagesForChatById(userId, chatId);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsVerifiedGuard()
    @UseGuards(JwtAuthGuard, VerifiedGuard)
    @Patch('me/:id/read') // handles single and bulk
    @ApiDocsMarkMessagesAsRead()
    async markMessageAsRead(
        @Req() req: Request,
        @Param('id') chatId: string,
        @Body() dto: MarkMessageAsReadDto,
    ) {
        const userId = req.tokenData!.sub;
        return this.chatService.markMessageAsRead(
            userId,
            chatId,
            dto.messageIds,
        );
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsVerifiedGuard()
    @UseGuards(JwtAuthGuard, VerifiedGuard)
    @UseInterceptors(FileInterceptor('file')) // "file" = form field name
    @Post('me/:id/upload')
    @ApiDocsSendImageMessage()
    async sendImage(
        @UploadedFile(
            new ParseFilePipe({
                validators: [
                    new MaxFileSizeValidator({ maxSize: 5 * 1024 * 1024 }),
                    new FileTypeValidator({
                        fileType: /^image\/(png|jpe?g|webp)$/i,
                        skipMagicNumbersValidation: true,
                    }),
                ],
            }),
        )
        file: Express.Multer.File,
        @Req() req: Request,
        @Param('id') chatId: string,
    ) {
        const userId = req.tokenData!.sub;
        return this.chatService.sendImageMessage(file, userId, chatId);
    }

    // Fake endpoint for docs
    @ApiDocsFakeWebSocketGuide()
    @Get('fake/websocket-guide')
    fakeWebSocketDocs() {
        return;
    }
}
