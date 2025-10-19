import { Module } from '@nestjs/common';
import { InvoiceService } from './invoice.service';
import { InvoiceController } from './invoice.controller';
import { BuyerModule } from 'src/buyer/buyer.module';
import { SupplierModule } from 'src/supplier/supplier.module';
import { ProductModule } from 'src/product/product.module';
import { ServiceModule } from 'src/service/service.module';
import { TapPaymentsModule } from 'src/tap-payments/tap-payments.module';
import { OfferModule } from 'src/offer/offer.module';
import { GroupPurchaseModule } from 'src/group-purchase/group-purchase.module';

@Module({
    imports: [
        BuyerModule,
        SupplierModule,
        ProductModule,
        ServiceModule,
        TapPaymentsModule,
        OfferModule,
        GroupPurchaseModule,
    ],
    controllers: [InvoiceController],
    providers: [InvoiceService],
})
export class InvoiceModule {}
