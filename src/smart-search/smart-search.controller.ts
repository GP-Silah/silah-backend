import { Controller, Get, Param } from '@nestjs/common';
import { SmartSearchService } from './smart-search.service';
import { ApiTags } from '@nestjs/swagger';

@ApiTags('Smart Search')
@Controller('smart-search')
export class SmartSearchController {
    constructor(private readonly smartSearchService: SmartSearchService) {}

    @Get(':itemId/similar')
    async getSimilarItems(@Param('itemId') itemId: string) {}
}
