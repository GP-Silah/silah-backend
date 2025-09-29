import { Module } from '@nestjs/common';
import { DemandPredictionService } from './demand-prediction.service';
import { DemandPredictionController } from './demand-prediction.controller';

@Module({
  controllers: [DemandPredictionController],
  providers: [DemandPredictionService],
})
export class DemandPredictionModule {}
