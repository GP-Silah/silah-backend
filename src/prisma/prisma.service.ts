import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService
    extends PrismaClient
    implements OnModuleInit, OnModuleDestroy
{
    logger: any;
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

        const modelKeys = Object.keys(this).filter(
            (key) =>
                !key.startsWith('$') &&
                typeof (this as any)[key] === 'object' &&
                typeof (this as any)[key]?.deleteMany === 'function',
        );

        return this.$transaction(async (tx) => {
            for (const key of modelKeys) {
                try {
                    await (tx as any)[key].deleteMany();
                } catch (error) {
                    this.logger.warn(
                        `Skipping ${key}: ${(error as Error).message}`,
                    );
                }
            }
        });
    }
}
