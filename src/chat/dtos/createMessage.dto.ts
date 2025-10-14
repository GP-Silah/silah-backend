import { IsOptional, IsString, IsUUID } from 'class-validator';

export class CreateMessageDto {
    @IsUUID()
    chatId: string;

    @IsUUID()
    senderId: string;

    @IsUUID()
    receiverId: string;

    @IsOptional()
    @IsString()
    text?: string;
}
