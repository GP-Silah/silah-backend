import { Module } from '@nestjs/common';
import { OfferService } from './offer.service';
import { OfferController } from './offer.controller';
import { BidModule } from 'src/bid/bid.module';
import { SupplierModule } from 'src/supplier/supplier.module';

@Module({
    imports: [BidModule, SupplierModule],
    controllers: [OfferController],
    providers: [OfferService],
})
export class OfferModule {}
