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
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import logger from './logger';
import { TapPaymentsModule } from './tap-payments/tap-payments.module';
import { SupplierModule } from './supplier/supplier.module';

@Module({
    imports: [
        TerminusModule,
        ThrottlerModule.forRoot([
            {
                ttl: 60, // Time to live = 60 seconds
                limit: 10, // Allow max 10 requests per IP per 60 seconds
            },
        ]),
        ScheduleModule.forRoot(),
        ConfigModule.forRoot({ isGlobal: true }),
        AuthModule,
        UserModule,
        PrismaModule,
        BuyerModule,
        FileModule,
        TapPaymentsModule,
        SupplierModule,
    ],
    controllers: [AppController, HealthController],
    providers: [
        AppService,
        {
            provide: APP_GUARD,
            useClass: ThrottlerGuard,
        },
        {
            provide: 'LOGGER',
            useValue: logger,
        },
    ],
})
export class AppModule {
    configure(consumer: MiddlewareConsumer) {
        consumer.apply(LoggerMiddleware).forRoutes('*');
    }
}
