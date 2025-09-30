import { Module } from '@nestjs/common';
import { BuyerService } from './buyer.service';
import { BuyerController } from './buyer.controller';
import { UserModule } from 'src/user/user.module';
import { TapPaymentsModule } from 'src/tap-payments/tap-payments.module';
import { ProductModule } from 'src/product/product.module';
import { ServiceModule } from 'src/service/service.module';

@Module({
    imports: [UserModule, TapPaymentsModule, ProductModule, ServiceModule],
    controllers: [BuyerController],
    providers: [BuyerService],
    exports: [BuyerService],
})
export class BuyerModule {}
