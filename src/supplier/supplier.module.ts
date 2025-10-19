import { Module } from '@nestjs/common';
import { SupplierService } from './supplier.service';
import { SupplierController } from './supplier.controller';
import { FileModule } from 'src/file/file.module';
import { UserModule } from 'src/user/user.module';
import { SupplierCronService } from './supplier-cron.service';

@Module({
    imports: [FileModule, UserModule],
    controllers: [SupplierController],
    providers: [SupplierService, SupplierCronService],
    exports: [SupplierService],
})
export class SupplierModule {}
