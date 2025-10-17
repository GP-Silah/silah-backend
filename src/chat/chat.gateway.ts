import {
    WebSocketGateway,
    WebSocketServer,
    SubscribeMessage,
    MessageBody,
    ConnectedSocket,
} from '@nestjs/websockets';
import * as cookie from 'cookie';
import { JwtService } from '@nestjs/jwt';
import { Server, Socket } from 'socket.io';
import { ChatService } from './chat.service';
import { MessageResponseDto } from './dtos/messageResonse.dto';
import { SendMessageDto } from './dtos/sendMessage.dto';
import {
    Inject,
    UnauthorizedException,
    Injectable,
    forwardRef,
} from '@nestjs/common';

@Injectable()
@WebSocketGateway({ cors: { origin: true, credentials: true } })
export class ChatGateway {
    constructor(
        @Inject(forwardRef(() => ChatService))
        private readonly chatService: ChatService,
        private readonly jwtService: JwtService,
    ) {}

    async handleConnection(client: Socket) {
        try {
            const rawCookies = client.handshake.headers.cookie || '';
            const parsedCookies = cookie.parse(rawCookies);
            let token = parsedCookies['token'];
            if (!token)
                throw new UnauthorizedException('No token found in cookies');

            // Strip the "j:" prefix if present
            if (token.startsWith('j:')) token = token.slice(2);

            // Now parse JSON if it looks like an object
            if (token.startsWith('{') && token.endsWith('}')) {
                const obj = JSON.parse(token);
                token = obj.token;
            }

            const payload = await this.jwtService.verifyAsync(token);
            (client as any).userId = payload.sub;
        } catch (err) {
            console.log('Invalid socket connection:', err.message);
            client.disconnect(true);
        }
    }

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
        const senderId = (client as any).userId;
        const { receiverId, chatId, text } = data;

        // 0. If no chatId → create chat first
        let finalChatId = chatId;
        if (!finalChatId) {
            const chat = await this.chatService.createChatIfNotExists(
                senderId,
                receiverId,
            );
            finalChatId = chat!.id;
            client.join(`chat_${finalChatId}`);
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
    handleJoinUser(@ConnectedSocket() client: Socket) {
        const userId = (client as any).userId;
        client.join(userId);
        client.emit('joined_user_room', userId);
    }

    @SubscribeMessage('typing')
    handleTyping(
        @ConnectedSocket() client: Socket,
        @MessageBody() data: { chatId: string },
    ) {
        const senderId = (client as any).userId;
        this.server.to(`chat_${data.chatId}`).emit('user_typing', senderId);
    }
}
