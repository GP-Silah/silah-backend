import { Global, Module } from '@nestjs/common';
import { NotificationService } from './notification.service';
import { NotificationController } from './notification.controller';
import { UserModule } from 'src/user/user.module';
import { TranslationModule } from 'src/translation/translation.module';

@Global()
@Module({
    imports: [UserModule, TranslationModule],
    controllers: [NotificationController],
    providers: [NotificationService],
    exports: [NotificationService],
})
export class NotificationModule {}
