import { Module } from '@nestjs/common';
import { GroupPurchaseService } from './group-purchase.service';
import { GroupPurchaseController } from './group-purchase.controller';
import { ProductModule } from 'src/product/product.module';
import { SupplierModule } from 'src/supplier/supplier.module';
import { BuyerModule } from 'src/buyer/buyer.module';

@Module({
    imports: [ProductModule, SupplierModule, BuyerModule],
    controllers: [GroupPurchaseController],
    providers: [GroupPurchaseService],
})
export class GroupPurchaseModule {}
