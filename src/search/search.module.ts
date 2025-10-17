import { Module } from '@nestjs/common';
import { SearchService } from './search.service';
import { SearchController } from './search.controller';
import { ProductModule } from 'src/product/product.module';
import { ServiceModule } from 'src/service/service.module';
import { SupplierModule } from 'src/supplier/supplier.module';
import { UserModule } from 'src/user/user.module';
import { ChatModule } from 'src/chat/chat.module';

@Module({
    imports: [
        ProductModule,
        ServiceModule,
        UserModule,
        SupplierModule,
        ChatModule,
    ],
    controllers: [SearchController],
    providers: [SearchService],
})
export class SearchModule {}
