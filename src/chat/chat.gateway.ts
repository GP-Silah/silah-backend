import {
    WebSocketGateway,
    WebSocketServer,
    SubscribeMessage,
    MessageBody,
    ConnectedSocket,
} from '@nestjs/websockets';
import { Server } from 'socket.io';

@WebSocketGateway({ cors: true })
export class ChatGateway {
    @WebSocketServer() server: Server;

    @SubscribeMessage('send_message')
    handleSendMessage(@MessageBody() data) {
        // 1. Save to DB (via ChatService)
        // 2. Emit to recipient socket
        // 3. Send notification to reciever (if the reciever is not on inside the chat page)
    }

    @SubscribeMessage('join_chat')
    handleJoinChat(@ConnectedSocket() client, @MessageBody() chatId: string) {
        client.join(`chat_${chatId}`);
    }
}
