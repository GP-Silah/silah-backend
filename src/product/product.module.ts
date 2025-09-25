import { Module } from '@nestjs/common';
import { ProductService } from './product.service';
import { ProductController } from './product.controller';
import { SupplierModule } from 'src/supplier/supplier.module';

@Module({
    imports: [SupplierModule],
    controllers: [ProductController],
    providers: [ProductService],
})
export class ProductModule {}
