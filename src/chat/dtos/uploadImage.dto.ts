import { IsUUID } from 'class-validator';

export class UploadImageDto {
    @IsUUID()
    chatId: string;

    @IsUUID()
    senderId: string;

    @IsUUID()
    receiverId: string;
}
