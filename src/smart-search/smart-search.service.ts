import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class SmartSearchService {
    constructor(private readonly prisma: PrismaService) {}

    async getSimilarItems(itemId: string) {}
}
