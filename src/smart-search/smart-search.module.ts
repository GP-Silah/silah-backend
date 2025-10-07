import { Module } from '@nestjs/common';
import { SmartSearchService } from './smart-search.service';
import { SmartSearchController } from './smart-search.controller';

@Module({
    controllers: [SmartSearchController],
    providers: [SmartSearchService],
    exports: [SmartSearchService],
})
export class SmartSearchModule {}
