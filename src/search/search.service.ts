import { Injectable } from '@nestjs/common';
import { User } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';
import { UserService } from 'src/user/user.service';

@Injectable()
export class SearchService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly userService: UserService,
    ) {}

    async searchUsers(name?: string) {
        // If no name is provided, return all users normally
        if (!name || name.trim() === '') {
            const allUsers = await this.prisma.user.findMany();
            return allUsers.map((user) =>
                this.userService.toUserResponseDTO(user),
            );
        }

        // FTS + fuzzy search
        const users = await this.prisma.$queryRaw<User[]>`
        SELECT 
            "id" AS "userId",
            "tapCustomerId",
            "name",
            "email",
            "crn",
            "businessName",
            "role",
            "city",
            "pfpFileName",
            "categories", //! check
            "isEmailVerified",
            "preferredLanguage",
            "createdAt",
            "updatedAt"
        FROM "User"
        WHERE to_tsvector('english', name) @@ plainto_tsquery('english', ${name})
           OR name % ${name}
        ORDER BY ts_rank(to_tsvector('english', name), plainto_tsquery('english', ${name})) DESC,
                 similarity(name, ${name}) DESC;
    `;

        return users.map((user) => this.userService.toUserResponseDTO(user));
    }
}
