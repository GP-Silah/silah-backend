import {
    ForbiddenException,
    Injectable,
    InternalServerErrorException,
} from '@nestjs/common';
import {
    Chat,
    Message,
    NotificationEntityType,
    NotificationType,
    User,
} from '@prisma/client';
import { FileService } from 'src/file/file.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { MessageResponseDto } from './dtos/messageResonse.dto';
import { UserResponseDTO } from 'src/user/dtos/userResponse.dto';
import { UserService } from 'src/user/user.service';
import { ChatResponseDto } from './dtos/chatResponse.dto';
import { NotificationService } from 'src/notification/notification.service';
import { ChatGateway } from './chat.gateway';

@Injectable()
export class ChatService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly fileService: FileService,
        private readonly userService: UserService,
        private readonly notificationService: NotificationService,
        private readonly chatGateway: ChatGateway,
    ) {}

    getOtherUserId(chat: any, userId: string): string {
        if (chat.user1Id === userId) return chat.user2Id;
        if (chat.user2Id === userId) return chat.user1Id;
        throw new ForbiddenException('User is not part of this chat');
    }

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
        const otherUserId = this.getOtherUserId(chat, loggedInUserId);
        const otherUserRaw =
            otherUserId === chat.user1.user.id ? chat.user1 : chat.user2;

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

    async getAllChats(userId: string): Promise<ChatResponseDto[]> {
        const chats = await this.prisma.chat.findMany({
            where: {
                OR: [{ user1Id: userId }, { user2Id: userId }],
            },
            include: {
                user1: {
                    include: {
                        firstChatUser: true,
                    },
                },
                user2: {
                    include: {
                        secondChatUser: true,
                    },
                },
                messages: {
                    orderBy: { createdAt: 'desc' },
                    take: 1, // only latest message
                },
            },
            orderBy: {
                updatedAt: 'desc', // most recent chats first
            },
        });

        // Compute unread counts efficiently (for optimization)
        const unreadCounts = await this.prisma.message.groupBy({
            by: ['chatId'],
            where: {
                receiverId: userId,
                isRead: false,
            },
            _count: { _all: true },
        });

        const unreadMap = Object.fromEntries(
            unreadCounts.map((c) => [c.chatId, c._count._all]),
        );

        // Map each chat to a DTO
        const dtos = await Promise.all(
            chats.map(async (chat) => {
                const dto = await this.toChatResponseDto(chat as any, userId);
                dto.unreadCount = unreadMap[chat.id] ?? 0;
                return dto;
            }),
        );

        return dtos;
    }

    async getMessagesForChatById(
        userId: string,
        chatId: string,
    ): Promise<MessageResponseDto[]> {
        // 1. Verify the user belongs to the chat
        const chat = await this.prisma.chat.findUnique({
            where: { id: chatId },
            select: { user1Id: true, user2Id: true },
        });

        if (!chat || (chat.user1Id !== userId && chat.user2Id !== userId)) {
            throw new ForbiddenException('You are not part of this chat.');
        }

        // 2. Fetch all messages in this chat
        const messages = await this.prisma.message.findMany({
            where: { chatId },
            include: {
                sender: { include: { sentMessages: true } },
                receiver: { include: { receivedMessages: true } },
            },
            orderBy: { createdAt: 'asc' },
        });

        // 3. Map each message to DTO
        const messageDtos = await Promise.all(
            messages.map(async (msg) => this.toMessageResponseDto(msg as any)),
        );

        return messageDtos;
    }

    async markMessageAsRead(
        userId: string,
        chatId: string,
        messageIds: string[],
    ) {
        // 1. Verify the user belongs to the chat
        const chat = await this.prisma.chat.findUnique({
            where: { id: chatId },
            select: { user1Id: true, user2Id: true },
        });

        if (!chat || (chat.user1Id !== userId && chat.user2Id !== userId)) {
            throw new ForbiddenException('You are not part of this chat.');
        }

        // 2. Mark messages as read —> only if user is the receiver
        const result = await this.prisma.message.updateMany({
            where: {
                id: { in: messageIds },
                chatId,
                receiverId: userId,
                isRead: false,
            },
            data: {
                isRead: true,
                readAt: new Date(),
            },
        });

        return {
            updatedCount: result.count,
            message: `${result.count} message(s) marked as read.`,
        };
    }

    async sendImageMessage(
        file: Express.Multer.File,
        userId: string,
        chatId: string,
    ) {
        const chat = await this.prisma.chat.findUnique({
            where: { id: chatId },
            select: { user1Id: true, user2Id: true },
        });
        if (!chat || (chat.user1Id !== userId && chat.user2Id !== userId)) {
            throw new ForbiddenException('You are not part of this chat.');
        }

        const fileName = await this.fileService.uploadFile(file);
        const receiverId = this.getOtherUserId(chat, userId);

        const message = await this.prisma.message.create({
            data: {
                chatId,
                senderId: userId,
                receiverId,
                text: null,
                imageFileName: fileName,
            },
            include: {
                sender: { include: { firstChatUser: true } },
                receiver: { include: { secondChatUser: true } },
            },
        });

        await this.prisma.chat.update({
            where: { id: chatId },
            data: { updatedAt: new Date() },
        });

        const messageDto = await this.toMessageResponseDto(message as any);

        this.chatGateway.emitNewMessage(chatId, messageDto);

        await this.notificationService.createNotification({
            senderUserId: userId,
            receiverUserId: receiverId,
            type: NotificationType.NEW_MESSAGE,
            title: `New message from ${message.sender.businessName}`,
            content: message.text ? message.text : 'Sent you an image',
            entityId: message.id,
            entityType: NotificationEntityType.CHAT,
        });

        return {
            message: 'Image sent successfully',
            data: messageDto,
        };
    }

    async createChatIfNotExists(user1Id: string, user2Id: string) {
        let chat = await this.prisma.chat.findFirst({
            where: {
                OR: [
                    { user1Id, user2Id },
                    { user1Id: user2Id, user2Id: user1Id },
                ],
            },
        });

        if (!chat) {
            try {
                chat = await this.prisma.chat.create({
                    data: { user1Id, user2Id },
                });
            } catch (e) {
                // Retry finding the chat in case it was created concurrently
                chat = await this.prisma.chat.findFirst({
                    where: {
                        OR: [
                            { user1Id, user2Id },
                            { user1Id: user2Id, user2Id: user1Id },
                        ],
                    },
                });
            }
        }

        return chat;
    }

    async createMessage(
        senderId: string,
        receiverId: string,
        chatId: string,
        text: string,
    ) {
        const message = await this.prisma.message.create({
            data: {
                chatId,
                senderId,
                receiverId,
                text,
                isRead: false,
            },
            include: {
                sender: { include: { firstChatUser: true } },
                receiver: { include: { secondChatUser: true } },
            },
        });

        // Create a notification for the receiver
        await this.notificationService.createNotification({
            senderUserId: senderId,
            receiverUserId: receiverId,
            type: NotificationType.NEW_MESSAGE,
            title: `New message from ${message.sender.businessName}`,
            content: message.text ?? 'Sent you an image',
            entityId: message.id,
            entityType: NotificationEntityType.CHAT,
        });

        return this.toMessageResponseDto(message as any);
    }
}
