import {
    WebSocketGateway,
    WebSocketServer,
    SubscribeMessage,
    MessageBody,
    ConnectedSocket,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { ChatService } from './chat.service';
import { MessageResponseDto } from './dtos/messageResonse.dto';
import { SendMessageDto } from './dtos/sendMessage.dto';

@WebSocketGateway({ cors: true })
export class ChatGateway {
    constructor(private readonly chatService: ChatService) {}

    @WebSocketServer() server: Server;

    @SubscribeMessage('join_chat')
    handleJoinChat(
        @ConnectedSocket() client: Socket,
        @MessageBody() chatId: string,
    ) {
        client.join(`chat_${chatId}`);
        client.emit('joined_chat', { chatId });
    }

    @SubscribeMessage('send_message')
    async handleSendMessage(
        @ConnectedSocket() client: Socket,
        @MessageBody() data: SendMessageDto,
    ) {
        const { senderId, receiverId, chatId, text } = data;

        // 0. If no chatId → create chat first
        let finalChatId = chatId;
        if (!finalChatId) {
            const chat = await this.chatService.createChatIfNotExists(
                senderId,
                receiverId,
            );
            finalChatId = chat!.id;
        }

        // 1. Save message + Send notification
        const message = await this.chatService.createMessage(
            senderId,
            receiverId,
            finalChatId,
            text,
        );

        // 2. Emit to the chat room
        this.server.to(`chat_${finalChatId}`).emit('new_message', message);

        // 3. Emit to receiver specifically (in case they aren’t in the chat)
        this.server.to(receiverId).emit('message_notification', {
            chatId: finalChatId,
            preview: text,
        });

        // 4. Acknowledge sender
        client.emit('message_sent', { chatId: finalChatId, message });
    }

    emitNewMessage(chatId: string, message: MessageResponseDto) {
        this.server.to(`chat_${chatId}`).emit('new_message', message);
    }

    @SubscribeMessage('join_user')
    handleJoinUser(
        @ConnectedSocket() client: Socket,
        @MessageBody() userId: string,
    ) {
        client.join(userId);
        client.emit('joined_user_room', userId);
    }

    @SubscribeMessage('typing')
    handleTyping(@MessageBody() data: { chatId: string; senderId: string }) {
        this.server
            .to(`chat_${data.chatId}`)
            .emit('user_typing', data.senderId);
    }
}
