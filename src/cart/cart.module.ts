import { Module } from '@nestjs/common';
import { CartService } from './cart.service';
import { CartController } from './cart.controller';
import { TranslationModule } from 'src/translation/translation.module';
import { TapPaymentsModule } from 'src/tap-payments/tap-payments.module';

@Module({
    imports: [TranslationModule, TapPaymentsModule],
    controllers: [CartController],
    providers: [CartService],
    exports: [CartService],
})
export class CartModule {}
