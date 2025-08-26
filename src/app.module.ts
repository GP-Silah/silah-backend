import { MiddlewareConsumer, Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UserModule } from './user/user.module';
import { AuthModule } from './auth/auth.module';
import { PrismaModule } from './prisma/prisma.module';
import { ScheduleModule } from '@nestjs/schedule';
import { BuyerModule } from './buyer/buyer.module';
import { FileModule } from './file/file.module';
import { HealthController } from './health/health.controller';
import { TerminusModule } from '@nestjs/terminus';
import { LoggerMiddleware } from './common/middleware/logger.middleware';

@Module({
    imports: [
        TerminusModule,
        ScheduleModule.forRoot(),
        AuthModule,
        UserModule,
        PrismaModule,
        BuyerModule,
        FileModule,
    ],
    controllers: [AppController, HealthController],
    providers: [AppService],
})
export class AppModule {
    configure(consumer: MiddlewareConsumer) {
        consumer.apply(LoggerMiddleware).forRoutes('*');
    }
}
