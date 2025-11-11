import { forwardRef, Module } from '@nestjs/common';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { AuthModule } from 'src/auth/auth.module';
import { FileModule } from 'src/file/file.module';
import { BuyerModule } from 'src/buyer/buyer.module';
import { SupplierModule } from 'src/supplier/supplier.module';

@Module({
    imports: [
        forwardRef(() => AuthModule),
        FileModule,
        forwardRef(() => BuyerModule),
        forwardRef(() => SupplierModule),
    ],
    controllers: [UserController],
    providers: [UserService],
    exports: [UserService],
})
export class UserModule {}
