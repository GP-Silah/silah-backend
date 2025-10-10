import { Controller, Get, Param, Req, UseGuards } from '@nestjs/common';
import { DemandPredictionService } from './demand-prediction.service';
import { Request } from 'express';
import { ApiDocsJwtAuthGuard } from 'src/auth/decorators/jwt-auth-guard.docs';
import { ApiDocsRolesGuard } from 'src/auth/decorators/roles-guard.docs';
import { UserRole } from 'src/enums/userRole.enum';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { ApiTags } from '@nestjs/swagger';
import { DemandPredictionResponseDto } from './dtos/demandPredictionResponse.dto';
import { ApiDocsGetDemandPrediction } from './demand-prediction.docs';
import { ApiDocsVerifiedGuard } from 'src/auth/decorators/verified-guard.docs';
import { VerifiedGuard } from 'src/auth/guards/verified.guard';

@ApiTags('Demand Predictions')
@Controller('demand-predictions')
export class DemandPredictionController {
    constructor(
        private readonly demandPredictionService: DemandPredictionService,
    ) {}

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @Get(':productId')
    @ApiDocsGetDemandPrediction()
    async getPredictionForProduct(
        @Param('productId') productId: string,
        @Req() req: Request,
    ): Promise<DemandPredictionResponseDto> {
        const userId = req.tokenData!.sub;
        return this.demandPredictionService.getPredictionForProduct(
            productId,
            userId,
        );
    }
}
