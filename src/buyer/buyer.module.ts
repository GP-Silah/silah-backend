import { Module } from '@nestjs/common';
import { BuyerService } from './buyer.service';
import { BuyerController } from './buyer.controller';
import { UserModule } from 'src/user/user.module';
import { TapPaymentsModule } from 'src/tap-payments/tap-payments.module';

@Module({
    imports: [UserModule, TapPaymentsModule],
    controllers: [BuyerController],
    providers: [BuyerService],
})
export class BuyerModule {}
