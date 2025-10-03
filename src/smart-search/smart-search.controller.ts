import { Controller, Post, Body } from '@nestjs/common';
import { SmartSearchService } from './smart-search.service';
import { ApiTags } from '@nestjs/swagger';
import { SmartSearchRequestDto } from './dtos/smartSearchRequest.dto';

@ApiTags('Smart Search')
@Controller('smart-search')
export class SmartSearchController {
    constructor(private readonly smartSearchService: SmartSearchService) {}

    @Post()
    async getSimilarItems(@Body() dto: SmartSearchRequestDto) {
        return this.smartSearchService.getSimilarItems(dto);
    }
}
