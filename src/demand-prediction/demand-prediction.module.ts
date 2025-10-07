import { Module } from '@nestjs/common';
import { DemandPredictionService } from './demand-prediction.service';
import { DemandPredictionController } from './demand-prediction.controller';
import { FileModule } from 'src/file/file.module';

@Module({
    imports: [FileModule],
    controllers: [DemandPredictionController],
    providers: [DemandPredictionService],
})
export class DemandPredictionModule {}
