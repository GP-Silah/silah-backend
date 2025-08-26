import { Test, TestingModule } from '@nestjs/testing';
import { HealthController } from '../../src/health/health.controller';
import { HealthCheckResult, HealthCheckService } from '@nestjs/terminus';

describe('HealthController', () => {
    let controller: HealthController;
    let healthCheckService: HealthCheckService;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            controllers: [HealthController],
            providers: [
                {
                    provide: HealthCheckService,
                    useValue: {
                        check: jest.fn(), // we'll mock this
                    },
                },
            ],
        }).compile();

        controller = module.get<HealthController>(HealthController);
        healthCheckService = module.get<HealthCheckService>(HealthCheckService);
    });

    it('should be defined', () => {
        expect(controller).toBeDefined();
    });

    it('should call HealthCheckService.check and return its value', async () => {
        const mockResult: HealthCheckResult = {
            status: 'ok',
            info: {},
            error: {},
            details: {},
        };
        jest.spyOn(healthCheckService, 'check').mockResolvedValue(mockResult);

        const result = await controller.check();
        expect(healthCheckService.check).toHaveBeenCalledWith([]);
        expect(result).toBe(mockResult);
    });
});
