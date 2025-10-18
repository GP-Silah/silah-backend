import { Module } from '@nestjs/common';
import { BidService } from './bid.service';
import { BidController } from './bid.controller';
import { BuyerModule } from 'src/buyer/buyer.module';

@Module({
    imports: [BuyerModule],
    controllers: [BidController],
    providers: [BidService],
})
export class BidModule {}
