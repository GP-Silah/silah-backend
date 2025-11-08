import { FileModule } from 'src/file/file.module';
import { forwardRef, Module } from '@nestjs/common';
import { ProductService } from './product.service';
import { ProductController } from './product.controller';
import { SupplierModule } from 'src/supplier/supplier.module';
import { TranslationModule } from 'src/translation/translation.module';
import { SmartSearchModule } from 'src/smart-search/smart-search.module';

@Module({
    imports: [
        FileModule,
        SupplierModule,
        TranslationModule,
        forwardRef(() => SmartSearchModule),
    ],
    controllers: [ProductController],
    providers: [ProductService],
    exports: [ProductService],
})
export class ProductModule {}
