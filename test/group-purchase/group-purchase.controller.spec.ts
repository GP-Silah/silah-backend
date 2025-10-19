import { Test, TestingModule } from '@nestjs/testing';
import { GroupPurchaseController } from '../../src/group-purchase/group-purchase.controller';
import { GroupPurchaseService } from '../../src/group-purchase/group-purchase.service';

describe('GroupPurchaseController', () => {
    let controller: GroupPurchaseController;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            controllers: [GroupPurchaseController],
            providers: [GroupPurchaseService],
        }).compile();

        controller = module.get<GroupPurchaseController>(
            GroupPurchaseController,
        );
    });

    it('should be defined', () => {
        expect(controller).toBeDefined();
    });
});
