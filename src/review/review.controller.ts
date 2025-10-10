import {
    Body,
    Controller,
    Get,
    Param,
    Post,
    Req,
    UseGuards,
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

@ApiTags('Reviews')
@Controller('reviews')
export class ReviewController {
    constructor(private readonly reviewService: ReviewService) {}

    @Get('suppliers/:supplierId')
    async getSupplierReviews(@Param('supplierId') supplierId: string) {
        return this.reviewService.getSupplierReviews(supplierId);
    }

    @Get(':reviewId')
    async getReviewById(@Param('reviewId') reviewId: string) {
        return this.reviewService.getReviewById(reviewId);
    }

    @Get('items/:itemId')
    async getItemReviews(@Param('itemId') itemId: string) {
        return this.reviewService.getItemReviews(itemId);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.BUYER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @Post(':id') // order or invoice id
    async createReview(
        @Param('id') id: string,
        @Req() req: Request,
        @Body() dto: CreateReviewDto,
    ) {}
}
