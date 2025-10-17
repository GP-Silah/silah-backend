import { Test, TestingModule } from '@nestjs/testing';
import { GroupPurchaseService } from '../../src/group-purchase/group-purchase.service';

describe('GroupPurchaseService', () => {
    let service: GroupPurchaseService;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [GroupPurchaseService],
        }).compile();

        service = module.get<GroupPurchaseService>(GroupPurchaseService);
    });

    it('should be defined', () => {
        expect(service).toBeDefined();
    });
});
