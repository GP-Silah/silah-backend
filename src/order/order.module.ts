import { Module } from '@nestjs/common';
import { OrderService } from './order.service';
import { OrderController } from './order.controller';
import { CartModule } from 'src/cart/cart.module';
import { BuyerModule } from 'src/buyer/buyer.module';
import { SupplierModule } from 'src/supplier/supplier.module';
import { ProductModule } from 'src/product/product.module';

@Module({
    imports: [CartModule, BuyerModule, SupplierModule, ProductModule],
    controllers: [OrderController],
    providers: [OrderService],
})
export class OrderModule {}
