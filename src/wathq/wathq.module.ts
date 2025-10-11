import { Module } from '@nestjs/common';
import { WathqService } from './wathq.service';

@Module({
    providers: [WathqService],
    exports: [WathqService],
})
export class WathqModule {}
