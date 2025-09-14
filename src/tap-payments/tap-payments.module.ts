// tap-payments.module.ts
import { Module } from '@nestjs/common';
import { TapPaymentsService } from './tap-payments.service';

@Module({
    providers: [TapPaymentsService],
    exports: [TapPaymentsService],
})
export class TapPaymentsModule {}
