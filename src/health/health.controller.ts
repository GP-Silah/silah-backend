import { Controller, Get } from '@nestjs/common';
import {
    HealthCheckService,
    HealthCheck,
    HealthIndicatorResult,
} from '@nestjs/terminus';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { PrismaService } from '../prisma/prisma.service';

@ApiTags('Health')
@Controller('health')
export class HealthController {
    constructor(
        private health: HealthCheckService,
        private prisma: PrismaService,
    ) {}

    @Get()
    @HealthCheck()
    @ApiOperation({ summary: 'Check API health status' })
    @ApiResponse({
        status: 200,
        description: 'API is healthy',
        schema: {
            example: {
                status: 'ok',
                info: { database: { status: 'up' } },
                error: {},
                details: { database: { status: 'up' } },
            },
        },
    })
    async check() {
        return this.health.check([
            // inline Prisma database check
            async (): Promise<HealthIndicatorResult> => {
                try {
                    await this.prisma.$queryRaw`SELECT 1`; // simple DB ping
                    return { database: { status: 'up' } };
                } catch (err) {
                    return {
                        database: { status: 'down', message: err.message },
                    };
                }
            },
        ]);
    }
}
