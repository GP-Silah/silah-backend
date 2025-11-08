import { forwardRef, Module } from '@nestjs/common';
import { SmartSearchService } from './smart-search.service';
import { SmartSearchController } from './smart-search.controller';
import { SupplierModule } from 'src/supplier/supplier.module';
import { ProductModule } from 'src/product/product.module';
import { ServiceModule } from 'src/service/service.module';

@Module({
    imports: [
        SupplierModule,
        forwardRef(() => ProductModule),
        forwardRef(() => ServiceModule),
    ],
    controllers: [SmartSearchController],
    providers: [SmartSearchService],
    exports: [SmartSearchService],
})
export class SmartSearchModule {}
