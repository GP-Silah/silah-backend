import { Controller, Get, Post, Body, Patch, Param } from '@nestjs/common';
import { ChatService } from './chat.service';
import { ApiTags } from '@nestjs/swagger';

@ApiTags('Chats')
@Controller('chats')
export class ChatController {
    constructor(private readonly chatService: ChatService) {}

    @Get('me')
    async getAllChats() {}

    @Get('me/:id/messages')
    async getMessagesByChatId() {}

    @Patch('me/:id/read')
    async markMessageAsRead() {}

    @Patch('me/read-many')
    async markMessageAsReadInBulk() {}

    @Post('me/:id/upload')
    async sendImage() {}
}
