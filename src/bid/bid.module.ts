import { Module } from '@nestjs/common';
import { BidService } from './bid.service';
import { BidController } from './bid.controller';
import { BuyerModule } from 'src/buyer/buyer.module';
import { BidCronService } from './bid-cron.service';

@Module({
    imports: [BuyerModule],
    controllers: [BidController],
    providers: [BidService, BidCronService],
    exports: [BidService],
})
export class BidModule {}
