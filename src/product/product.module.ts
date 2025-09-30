import { FileModule } from 'src/file/file.module';
import { Module } from '@nestjs/common';
import { ProductService } from './product.service';
import { ProductController } from './product.controller';
import { SupplierModule } from 'src/supplier/supplier.module';
import { TranslationModule } from 'src/translation/translation.module';

@Module({
    imports: [FileModule, SupplierModule, TranslationModule],
    controllers: [ProductController],
    providers: [ProductService],
    exports: [ProductService],
})
export class ProductModule {}
