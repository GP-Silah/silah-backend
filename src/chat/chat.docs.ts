import { applyDecorators } from '@nestjs/common';
import {
    ApiOperation,
    ApiResponse,
    ApiBearerAuth,
    ApiConsumes,
    ApiBody,
    ApiNotFoundResponse,
    ApiBadRequestResponse,
    ApiQuery,
} from '@nestjs/swagger';
import { MessageResponseDto } from './dtos/messageResonse.dto';
import { ChatResponseDto } from './dtos/chatResponse.dto';
import { MarkMessageAsReadDto } from './dtos/markMessageAsRead.dto';

// ------------------------ GET ALL CHATS (WITH FILTERS) ------------------------
export function ApiDocsGetAllChats() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary:
                'Get all chats of the logged-in user (with optional filters)',
            description: `Fetches all chats for the currently authenticated and verified user.
                Each chat includes:
                <ul>
                    <li>Other user's details</li>
                    <li>Last message (text or image)</li>
                    <li>Unread message count</li>
                    <li>Last message timestamp</li>
                </ul>
                <br/>
                You can optionally filter the chats using query parameters:
                <ul>
                    <li><b>date</b> — Filter by recent activity:</li>
                        <ul>
                            <li><code>all</code> — All chats (default)</li>
                            <li><code>today</code> — Chats with messages sent today</li>
                            <li><code>this-week</code> — Chats active during this week</li>
                            <li><code>this-month</code> — Chats active during this month</li>
                        </ul>
                    <li><b>status</b> — Filter by message read state:</li>
                        <ul>
                            <li><code>all</code> — Show all chats (default)</li>
                            <li><code>unread</code> — Only chats that have unread messages</li>
                            <li><code>read</code> — Only chats where all messages are read</li>
                        </ul>
                </ul>
                You can combine filters, for example:
                <code>?date=this-week&status=unread</code> to show unread chats from this week.`,
        }),
        ApiQuery({
            name: 'date',
            required: false,
            enum: ['all', 'today', 'this-week', 'this-month'],
            description:
                'Filter chats based on latest message date (default: all)',
        }),
        ApiQuery({
            name: 'status',
            required: false,
            enum: ['all', 'unread', 'read'],
            description:
                'Filter chats based on read/unread state (default: all)',
        }),
        ApiResponse({
            status: 200,
            description:
                'List of chats for the logged-in user (filtered if applicable)',
            type: [ChatResponseDto],
        }),
    );
}

// ------------------------ GET MESSAGES FOR A CHAT ------------------------
export function ApiDocsGetMessagesForChat() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Get messages for a specific chat',
            description: `Fetches all messages for the given <code>chatId</code> that belongs to the logged-in user.
                Messages include sender/receiver details, text, image (if any), and read status.`,
        }),
        ApiResponse({
            status: 200,
            description: 'Messages for the specified chat',
            type: [MessageResponseDto],
        }),
        ApiNotFoundResponse({
            description: 'Chat not found or user not part of it',
            schema: {
                example: {
                    statusCode: 403,
                    message: 'You are not part of this chat.',
                    error: 'Forbidden',
                },
            },
        }),
    );
}

// ------------------------ MARK MESSAGES AS READ ------------------------
export function ApiDocsMarkMessagesAsRead() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Mark one or more messages as read',
            description: `Marks messages as read for the given <code>chatId</code>.<br>
                Only messages received by the current user can be marked as read.<br><br>`,
        }),
        ApiBody({
            type: MarkMessageAsReadDto,
            description: 'Array of message IDs to mark as read',
        }),
        ApiResponse({
            status: 200,
            description: 'Number of messages marked as read',
            schema: {
                example: {
                    updatedCount: 2,
                    message: '2 message(s) marked as read.',
                },
            },
        }),
        ApiBadRequestResponse({
            description: 'Invalid message IDs or chat mismatch',
            schema: {
                example: {
                    statusCode: 400,
                    message: 'You are not part of this chat.',
                    error: 'Bad Request',
                },
            },
        }),
    );
}

// ------------------------ SEND IMAGE MESSAGE ------------------------
export function ApiDocsSendImageMessage() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Send an image in a chat',
            description: `Sends an image message in an existing chat.<br>
                <strong>Note:</strong> This endpoint requires sending <u>multipart/form-data</u>.<br><br>
                <strong>File requirements:</strong>
                <ul>
                    <li>Field name: <code>file</code></li>
                    <li>Allowed formats: PNG, JPEG, WEBP</li>
                    <li>Max size: 5MB</li>
                </ul>
            <strong>IMPORTANT:</strong> Please ensure that uploaded images comply with Islamic laws. This means avoiding haram content such as music-related images, depictions of women's bodies (even hands), or any illustrations of living beings (humans, animals, etc.) whether drawn or digital.`,
        }),
        ApiConsumes('multipart/form-data'),
        ApiBody({
            schema: {
                type: 'object',
                properties: {
                    file: {
                        type: 'string',
                        format: 'binary',
                        description:
                            'Chat image file (PNG, JPEG, WEBP, max 5MB)',
                    },
                },
                required: ['file'],
            },
        }),
        ApiResponse({
            status: 201,
            description: 'Image sent successfully',
            schema: {
                example: {
                    message: 'Image sent successfully',
                    data: {
                        messageId: 'msg_123',
                        chatId: 'chat_456',
                        sender: {
                            id: 'usr_789',
                            name: 'Shahad Bakery',
                        },
                        receiver: {
                            id: 'usr_101',
                            name: 'Customer A',
                        },
                        imageUrl: 'https://cdn.example.com/uploads/file.webp',
                        isRead: false,
                        createdAt: '2025-10-17T15:10:00Z',
                    },
                },
            },
        }),
        ApiBadRequestResponse({
            description: 'File validation failed',
            schema: {
                example: {
                    statusCode: 400,
                    message:
                        'File too large (max 5MB) or invalid format (only PNG, JPEG, WEBP allowed)',
                    error: 'Bad Request',
                },
            },
        }),
    );
}

// ------------------------ FAKE ENDPOINT: WEBSOCKET DOC ------------------------
export function ApiDocsFakeWebSocketGuide() {
    return applyDecorators(
        ApiOperation({
            deprecated: true,
            summary:
                '⚠️ Swagger-only reference: WebSocket Chat Events Guide (NOT a real endpoint)',
            description: `⚠️ **This endpoint does NOT exist in the real API.**  
It is a _Swagger-only documentation_ to help developers understand how to connect to and use the **Chat WebSocket Gateway**.

**Base Socket URL:**  
\`https://api.silah.site\` (same host as REST API, automatically maps HTTPS to WSS)  
**Namespace:** Default (no prefix)  
**Authorization:** Token is sent via cookies (JWT in \`token\` cookie)

### Available Events

| Event          | Direction      | Description                                                        | Example Payload |
|----------------|----------------|--------------------------------------------------------------------|----------------|
| \`join_user\`    | client → server | Joins the user's personal room for receiving direct notifications | \`{}\` |
| \`join_chat\`    | client → server | Join a chat room to receive its messages                          | \`{ "chatId": "chat_123" }\` |
| \`send_message\` | client → server | Sends a text message. If no \`chatId\` provided, a new chat is auto-created | \`{ "receiverId": "user_456", "chatId": "chat_123", "text": "السلام عليكم" }\` |
| \`new_message\`  | server → client | Emitted when a new message is received in the joined chat room     | See below |
| \`typing\`       | client → server | Notifies others in the chat that the user is typing               | \`{ "chatId": "chat_123" }\` |
| \`user_typing\`  | server → client | Broadcasted when someone else in the chat is typing               | \`{ "userId": "user_123" }\` |

### Detailed Example Payloads

**new_message (server → client):**

\`\`\`json
{
  "messageId": "msg_abc",
  "chatId": "chat_123",
  "sender": { "id": "user_123", "name": "Shahad Bakery" },
  "receiver": { "id": "user_456", "name": "Client" },
  "text": "مرحبا!",
  "createdAt": "2025-10-17T15:20:00Z"
}
\`\`\`

### Successful Connection Example (Client)

\`\`\`js
import { io } from "socket.io-client";

const socket = io("https://api.silah.site", { withCredentials: true });

socket.emit("join_user");
socket.emit("join_chat", "chat_123");
socket.emit("send_message", { receiverId: "user_456", text: "Hello!" });

socket.on("new_message", (message) => console.log(message));
\`\`\`

**Note:** The socket connection automatically validates the JWT token from cookies and disconnects unauthorized users.
      `,
        }),
        ApiResponse({
            status: 200,
            description: 'This endpoint returns nothing',
        }),
    );
}
