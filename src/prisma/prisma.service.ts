import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService
    extends PrismaClient
    implements OnModuleInit, OnModuleDestroy
{
    constructor() {
        super();
    }

    async onModuleInit() {
        await this.$connect();
    }

    async onModuleDestroy() {
        await this.$disconnect();
    }

    async cleanDatabase() {
        if (process.env.NODE_ENV === 'production') return;
        const models = Object.keys(this).filter(
            (key) => typeof this[key] === 'object' && 'deleteMany' in this[key],
        );
        return Promise.all(
            models.map(async (model) => {
                try {
                    await this[model].deleteMany();
                } catch (error) {
                    console.warn(`Skipping ${model}:`, error.message);
                }
            }),
        );
    }
}
