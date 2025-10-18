import { Module } from '@nestjs/common';
import { ReviewService } from './review.service';
import { ReviewController } from './review.controller';
import { BuyerModule } from 'src/buyer/buyer.module';
import { SupplierModule } from 'src/supplier/supplier.module';
import { ProductModule } from 'src/product/product.module';
import { ServiceModule } from 'src/service/service.module';
import { TranslationModule } from 'src/translation/translation.module';

@Module({
    imports: [
        BuyerModule,
        SupplierModule,
        ProductModule,
        ServiceModule,
        TranslationModule,
    ],
    controllers: [ReviewController],
    providers: [ReviewService],
    exports: [ReviewService],
})
export class ReviewModule {}
