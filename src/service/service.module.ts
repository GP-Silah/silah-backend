import { Module } from '@nestjs/common';
import { ServiceService } from './service.service';
import { ServiceController } from './service.controller';
import { FileModule } from 'src/file/file.module';
import { SupplierModule } from 'src/supplier/supplier.module';
import { TranslationModule } from 'src/translation/translation.module';
import { SmartSearchModule } from 'src/smart-search/smart-search.module';

@Module({
    imports: [FileModule, SupplierModule, TranslationModule, SmartSearchModule],
    controllers: [ServiceController],
    providers: [ServiceService],
    exports: [ServiceService],
})
export class ServiceModule {}
