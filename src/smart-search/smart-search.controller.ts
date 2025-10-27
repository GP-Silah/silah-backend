import { Controller, Post, Body, Req, Query, Headers } from '@nestjs/common';
import { SmartSearchService } from './smart-search.service';
import { ApiTags } from '@nestjs/swagger';
import { SmartSearchRequestDto } from './dtos/smartSearchRequest.dto';
import { ApiDocsSmartSearch } from './smart-search.docs';
import { Request } from 'express';

@ApiTags('Smart Search')
@Controller('smart-search')
export class SmartSearchController {
    constructor(private readonly smartSearchService: SmartSearchService) {}

    /** Helper function to determine target language */
    private async resolveTargetLang(
        req: Request,
        lang?: 'ar' | 'en',
        langHeader?: 'ar' | 'en',
    ) {
        let targetLang: 'ar' | 'en' = 'en';

        // Priority: query param > header > user preference > default
        if (lang) {
            targetLang = lang;
        } else if (langHeader) {
            targetLang = langHeader;
        } else if (req.tokenData?.sub) {
            const user = await this.smartSearchService.getUserLanguage(
                req.tokenData.sub,
            );
            if (user) targetLang = user;
        }

        return targetLang;
    }

    @Post()
    @ApiDocsSmartSearch()
    async getSimilarItems(
        @Body() dto: SmartSearchRequestDto,
        @Req() req: Request,
        @Headers('accept-language') langHeader?: 'ar' | 'en',
        @Query('lang') lang?: 'ar' | 'en',
    ) {
        const targetLang = await this.resolveTargetLang(req, lang, langHeader);
        return this.smartSearchService.getSimilarItems(dto, targetLang);
    }
}
