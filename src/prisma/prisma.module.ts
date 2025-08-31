import { Global, Module } from '@nestjs/common';
import { PrismaService } from './prisma.service';
import logger from 'src/logger';

@Global() // This makes it available app-wide without re-importing
@Module({
    providers: [
        PrismaService,
        {
            provide: 'LOGGER',
            useValue: logger, // or a mock in tests
        },
    ],
    exports: [PrismaService],
})
export class PrismaModule {}
