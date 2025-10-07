import { Module } from '@nestjs/common';
import { SearchService } from './search.service';
import { SearchController } from './search.controller';
import { ProductModule } from 'src/product/product.module';
import { ServiceModule } from 'src/service/service.module';
import { SupplierModule } from 'src/supplier/supplier.module';
import { UserModule } from 'src/user/user.module';

@Module({
    imports: [ProductModule, ServiceModule, UserModule, SupplierModule],
    controllers: [SearchController],
    providers: [SearchService],
})
export class SearchModule {}
