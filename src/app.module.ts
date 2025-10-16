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
import { CategoryModule } from './category/category.module';
import { ProductModule } from './product/product.module';
import { ServiceModule } from './service/service.module';
import { CartModule } from './cart/cart.module';
import { DemandPredictionModule } from './demand-prediction/demand-prediction.module';
import { OrderModule } from './order/order.module';
import { TranslationModule } from './translation/translation.module';
import { SmartSearchModule } from './smart-search/smart-search.module';
import { SearchModule } from './search/search.module';
import { InvoiceModule } from './invoice/invoice.module';
import { ReviewModule } from './review/review.module';
import { NotificationModule } from './notification/notification.module';
import { ChatModule } from './chat/chat.module';

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
        PrismaModule,
        FileModule,
        TapPaymentsModule,
        TranslationModule,
        AuthModule,
        UserModule,
        BuyerModule,
        SupplierModule,
        CategoryModule,
        ProductModule,
        ServiceModule,
        CartModule,
        OrderModule,
        DemandPredictionModule,
        SmartSearchModule,
        SearchModule,
        InvoiceModule,
        ReviewModule,
        NotificationModule,
        ChatModule,
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
