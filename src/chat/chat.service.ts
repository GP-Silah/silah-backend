import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { Chat, Message, User } from '@prisma/client';
import { FileService } from 'src/file/file.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { MessageResponseDto } from './dtos/messageResonse.dto';
import { UserResponseDTO } from 'src/user/dtos/userResponse.dto';
import { UserService } from 'src/user/user.service';
import { ChatResponseDto } from './dtos/chatResponse.dto';

@Injectable()
export class ChatService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly fileService: FileService,
        private readonly userService: UserService,
    ) {}

    /**
     * Maps a Prisma Message object (with sender & receiver included) to MessageResponseDto
     */
    async toMessageResponseDto(
        message: Message & {
            sender: {
                user: User;
            };
            receiver: {
                user: User;
            };
        },
    ): Promise<MessageResponseDto> {
        const senderDto: UserResponseDTO =
            await this.userService.toUserResponseDTO(message.sender.user);

        const receiverDto: UserResponseDTO =
            await this.userService.toUserResponseDTO(message.receiver.user);

        const imageUrl = message.imageFileName
            ? await this.fileService.getFileUrl(message.imageFileName)
            : undefined;

        return {
            messageId: message.id,
            chatId: message.chatId,
            sender: senderDto,
            receiver: receiverDto,
            text: message.text ?? undefined,
            imageUrl,
            isRead: message.isRead,
            readAt: message.readAt ?? undefined,
            createdAt: message.createdAt,
        };
    }

    /**
     * Maps a Prisma Chat object to ChatResponseDto
     * @param chat Chat object, should include user1, user2, lastMessage info
     * @param loggedInUserId the ID of the currently logged-in user
     */
    async toChatResponseDto(
        chat: Chat & {
            user1: {
                user: User;
            };
            user2: {
                user: User;
            };
            messages: Message[];
        },
        loggedInUserId: string,
    ): Promise<ChatResponseDto> {
        // Determine the other participant
        const otherUserRaw =
            chat.user1.user.id === loggedInUserId ? chat.user2 : chat.user1;

        const otherUser: UserResponseDTO =
            await this.userService.toUserResponseDTO(otherUserRaw.user);

        // Determine the latest message
        let lastMessageText: string | undefined;
        let lastMessageIsImage: boolean;
        let lastMessageAt: Date;

        if (chat.messages && chat.messages.length > 0) {
            // Assume messages are sorted by createdAt descending
            const lastMessage = chat.messages[0];
            lastMessageText = lastMessage.text ?? undefined;
            lastMessageIsImage = lastMessage.imageFileName ? true : false;
            lastMessageAt = lastMessage.createdAt;
        } else {
            throw new InternalServerErrorException(
                'Chats should always have one message at least.',
            );
        }

        // Calculate unread count if messages are included
        const unreadCount =
            chat.messages?.filter(
                (m) => !m.isRead && m.receiverId === loggedInUserId,
            ).length ?? 0;

        return {
            chatId: chat.id,
            otherUser,
            lastMessageText,
            lastMessageIsImage,
            lastMessageAt,
            unreadCount,
        };
    }
}
