import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UserModule } from './user/user.module';
import { AuthModule } from './auth/auth.module';
import { PrismaModule } from './prisma/prisma.module';
import { ScheduleModule } from '@nestjs/schedule';
import { BuyerModule } from './buyer/buyer.module';

@Module({
    imports: [ScheduleModule.forRoot(), AuthModule, UserModule, PrismaModule, BuyerModule],
    controllers: [AppController],
    providers: [AppService],
})
export class AppModule {}
