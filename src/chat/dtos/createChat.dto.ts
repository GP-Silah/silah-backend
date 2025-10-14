import { IsUUID } from 'class-validator';

export class CreateChatDto {
    @IsUUID()
    user1Id: string;

    @IsUUID()
    user2Id: string;
}
