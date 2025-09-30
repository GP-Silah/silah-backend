import { Test, TestingModule } from '@nestjs/testing';
import { DemandPredictionController } from '../../src/demand-prediction/demand-prediction.controller';
import { DemandPredictionService } from '../../src/demand-prediction/demand-prediction.service';

describe('DemandPredictionController', () => {
    let controller: DemandPredictionController;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            controllers: [DemandPredictionController],
            providers: [DemandPredictionService],
        }).compile();

        controller = module.get<DemandPredictionController>(
            DemandPredictionController,
        );
    });

    it('should be defined', () => {
        expect(controller).toBeDefined();
    });
});
