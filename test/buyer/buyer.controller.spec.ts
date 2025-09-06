import { Test, TestingModule } from '@nestjs/testing';
import { BuyerController } from '../../src/buyer/buyer.controller';
import { BuyerService } from '../../src/buyer/buyer.service';

describe('BuyerController', () => {
    let controller: BuyerController;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            controllers: [BuyerController],
            providers: [BuyerService],
        }).compile();

        controller = module.get<BuyerController>(BuyerController);
    });

    it('should be defined', () => {
        expect(controller).toBeDefined();
    });
});
