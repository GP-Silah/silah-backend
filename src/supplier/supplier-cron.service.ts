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

        // 1. Find all suppliers who used free trial
        const suppliers = await this.prisma.supplier.findMany({
            where: { usedFreeTrail: true },
            include: { subscriptions: true },
        });

        const today = new Date();

        for (const supplier of suppliers) {
            // 2. Find the subscription that represents the free trial
            const trialSubscription = supplier.subscriptions.find(
                (s) =>
                    s.startDate &&
                    s.endDate &&
                    supplier.plan === SupplierPlan.PREMIUM,
            );

            if (!trialSubscription) continue;

            const daysSinceTrialStart =
                (today.getTime() - trialSubscription.startDate.getTime()) /
                (1000 * 60 * 60 * 24);

            if (daysSinceTrialStart < 30) continue; // still in trial

            // TODO: Replace with actual counts from products/services tables
            const productCount = 0; // await this.countSupplierProducts(supplier.id);
            const serviceCount = 0; // await this.countSupplierServices(supplier.id);

            if (productCount <= 10 && serviceCount <= 3) {
                // Downgrade plan to BASIC if within limits
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
                // Exceeded limits → inactive
                await this.prisma.supplier.update({
                    where: { id: supplier.id },
                    data: {
                        plan: SupplierPlan.BASIC,
                        status: SupplierStatus.INACTIVE,
                    },
                });
                this.logger.debug(
                    `Supplier ${supplier.id} exceeded limits → set to INACTIVE and BASIC plan.`,
                );
            }
        }

        this.logger.debug('Supplier plan check cron job completed.');
    }

    // TODO: Implement these methods when products/services tables exist
    /*
    private async countSupplierProducts(supplierId: string): Promise<number> {}
    private async countSupplierServices(supplierId: string): Promise<number> {}
    */
}
