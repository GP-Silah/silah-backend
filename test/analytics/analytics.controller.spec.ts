import { Test, TestingModule } from '@nestjs/testing';
import { AnalyticsController } from '../../src/analytics/analytics.controller';
import { AnalyticsService } from '../../src/analytics/analytics.service';

describe('AnalyticsController', () => {
    let controller: AnalyticsController;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            controllers: [AnalyticsController],
            providers: [AnalyticsService],
        }).compile();

        controller = module.get<AnalyticsController>(AnalyticsController);
    });

    it('should be defined', () => {
        expect(controller).toBeDefined();
    });
});
