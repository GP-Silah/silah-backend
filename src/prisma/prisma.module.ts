import { Global, Module } from '@nestjs/common';
import { PrismaService } from './prisma.service';

@Global() // This makes it available app-wide without re-importing
@Module({
    providers: [PrismaService],
    exports: [PrismaService],
})
export class PrismaModule {}
