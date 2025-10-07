import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { PrismaService } from 'src/prisma/prisma.service';
import { SupplierPlan, SupplierStatus } from '@prisma/client';

@Injectable()
export class SupplierCronService {
    private readonly logger = new Logger(SupplierCronService.name);

    constructor(private readonly prisma: PrismaService) {}

    @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
    async handleSupplierPlans() {
        this.logger.debug('Running supplier plan check cron job...');

        // 1. Find all suppliers who used free trial and are on PREMIUM
        const suppliers = await this.prisma.supplier.findMany({
            where: { usedFreeTrail: true, plan: SupplierPlan.PREMIUM },
            include: { subscriptions: true },
        });

        const today = new Date();

        for (const supplier of suppliers) {
            // 2. Find the free trial subscription
            const trialSubscription = supplier.subscriptions.find(
                (s) => s.startDate && s.endDate,
            );
            if (!trialSubscription) continue;

            const daysSinceTrialStart =
                (today.getTime() - trialSubscription.startDate.getTime()) /
                (1000 * 60 * 60 * 24);

            if (daysSinceTrialStart < 30) continue; // still in trial

            // 3. Count products and services for this supplier
            const productCount = await this.countSupplierProducts(supplier.id);
            const serviceCount = await this.countSupplierServices(supplier.id);

            // 4. Apply downgrade logic
            if (productCount <= 10 && serviceCount <= 3) {
                await this.prisma.supplier.update({
                    where: { id: supplier.id },
                    data: {
                        plan: SupplierPlan.BASIC,
                        status: SupplierStatus.ACTIVE,
                    },
                });
                this.logger.debug(
                    `Supplier ${supplier.id} downgraded to BASIC plan (within limits).`,
                );
            } else {
                await this.prisma.supplier.update({
                    where: { id: supplier.id },
                    data: {
                        plan: SupplierPlan.BASIC,
                        status: SupplierStatus.INACTIVE,
                    },
                });
                this.logger.debug(
                    `Supplier ${supplier.id} exceeded limits → downgraded to BASIC and set INACTIVE.`,
                );
            }
        }

        this.logger.debug('Supplier plan check cron job completed.');
    }

    private async countSupplierProducts(supplierId: string): Promise<number> {
        return this.prisma.product.count({
            where: { supplierId, isDeleted: false },
        });
    }

    private async countSupplierServices(supplierId: string): Promise<number> {
        return this.prisma.service.count({
            where: { supplierId, isDeleted: false },
        });
    }
}
