import { Test, TestingModule } from '@nestjs/testing';
import { HealthController } from '../../src/health/health.controller';
import { HealthCheckResult, HealthCheckService } from '@nestjs/terminus';
import { PrismaService } from 'src/prisma/prisma.service';

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
                        check: jest.fn(),
                    },
                },
                {
                    provide: PrismaService,
                    useValue: {
                        $queryRaw: jest.fn(), // mock the DB ping
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

    it('should call HealthCheckService.check with indicators and return its value', async () => {
        const mockResult: HealthCheckResult = {
            status: 'ok',
            info: { database: { status: 'up' } },
            error: {},
            details: { database: { status: 'up' } },
        };

        const indicators = [expect.any(Function)]; // Jest matcher for the function array
        jest.spyOn(healthCheckService, 'check').mockResolvedValue(mockResult);

        const result = await controller.check();

        expect(healthCheckService.check).toHaveBeenCalledWith(indicators);
        expect(result).toBe(mockResult);
    });
});
