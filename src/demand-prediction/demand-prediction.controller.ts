import { Controller, Get, Param, Req, UseGuards } from '@nestjs/common';
import { DemandPredictionService } from './demand-prediction.service';
import { Request } from 'express';
import { ApiJwtAuthGuard } from 'src/auth/decorators/api-jwt-auth-guard.docs';
import { ApiRolesGuard } from 'src/auth/decorators/api-roles-guard.docs';
import { UserRole } from 'src/enums/userRole.enum';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { ApiTags } from '@nestjs/swagger';

@ApiTags('Demand Predictions')
@Controller('demand-predictions')
export class DemandPredictionController {
    constructor(
        private readonly demandPredictionService: DemandPredictionService,
    ) {}

    @ApiJwtAuthGuard()
    @ApiRolesGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Get(':productId')
    async getPredictionForProduct(
        @Param('productId') productId: string,
        @Req() req: Request,
    ) {
        const userId = req.tokenData!.sub;
        return this.demandPredictionService.getPredictionForProduct(
            productId,
            userId,
        );
    }
}
