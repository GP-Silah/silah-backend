import { IsArray, IsUUID } from 'class-validator';

export class MarkMessageAsReadDto {
    @IsUUID()
    chatId: string;

    @IsArray()
    @IsUUID('4', { each: true })
    messageIds: string[];
}
