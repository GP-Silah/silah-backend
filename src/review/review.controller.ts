import {
    Body,
    Controller,
    Get,
    Param,
    Post,
    Req,
    UseGuards,
    Headers,
    Query,
} from '@nestjs/common';
import { ReviewService } from './review.service';
import { ApiTags } from '@nestjs/swagger';
import { Request } from 'express';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { UserRole } from 'src/enums/userRole.enum';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { VerifiedGuard } from 'src/auth/guards/verified.guard';
import { ApiDocsJwtAuthGuard } from 'src/auth/decorators/jwt-auth-guard.docs';
import { ApiDocsRolesGuard } from 'src/auth/decorators/roles-guard.docs';
import { ApiDocsVerifiedGuard } from 'src/auth/decorators/verified-guard.docs';
import { CreateReviewDto } from './dtos/createReview.dto';
import {
    ApiDocsCreateReview,
    ApiDocsGetItemReviews,
    ApiDocsGetReviewById,
    ApiDocsGetSupplierReviews,
} from './review.docs';

@ApiTags('Reviews')
@Controller('reviews')
export class ReviewController {
    constructor(private readonly reviewService: ReviewService) {}

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
            const user = await this.reviewService.getUserLanguage(
                req.tokenData.sub,
            );
            if (user) targetLang = user;
        }

        return targetLang;
    }

    @Get('suppliers/:supplierId')
    @ApiDocsGetSupplierReviews()
    async getSupplierReviews(
        @Req() req: Request,
        @Param('supplierId') supplierId: string,
        @Headers('accept-language') langHeader?: 'ar' | 'en',
        @Query('lang') lang?: 'ar' | 'en',
    ) {
        const targetLang = await this.resolveTargetLang(req, lang, langHeader);
        return this.reviewService.getSupplierReviews(supplierId, targetLang);
    }

    @Get(':reviewId')
    @ApiDocsGetReviewById()
    async getReviewById(@Param('reviewId') reviewId: string) {
        return this.reviewService.getReviewById(reviewId);
    }

    @Get('items/:itemId')
    @ApiDocsGetItemReviews()
    async getItemReviews(
        @Req() req: Request,
        @Param('itemId') itemId: string,
        @Headers('accept-language') langHeader?: 'ar' | 'en',
        @Query('lang') lang?: 'ar' | 'en',
    ) {
        const targetLang = await this.resolveTargetLang(req, lang, langHeader);
        return this.reviewService.getItemReviews(itemId, targetLang);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @Post(':id') // order or invoice id
    @ApiDocsCreateReview()
    async createReview(
        @Param('id') id: string,
        @Req() req: Request,
        @Body() dto: CreateReviewDto,
    ) {
        const userId = req.tokenData!.sub;
        return this.reviewService.createReview(userId, id, dto);
    }
}
