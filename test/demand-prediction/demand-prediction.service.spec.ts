import { Test, TestingModule } from '@nestjs/testing';
import { DemandPredictionService } from '../../src/demand-prediction/demand-prediction.service';

describe('DemandPredictionService', () => {
    let service: DemandPredictionService;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [DemandPredictionService],
        }).compile();

        service = module.get<DemandPredictionService>(DemandPredictionService);
    });

    it('should be defined', () => {
        expect(service).toBeDefined();
    });
});
