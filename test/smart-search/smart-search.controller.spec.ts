import { Test, TestingModule } from '@nestjs/testing';
import { SmartSearchController } from '../../src/smart-search/smart-search.controller';
import { SmartSearchService } from '../../src/smart-search/smart-search.service';

describe('SmartSearchController', () => {
    let controller: SmartSearchController;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            controllers: [SmartSearchController],
            providers: [SmartSearchService],
        }).compile();

        controller = module.get<SmartSearchController>(SmartSearchController);
    });

    it('should be defined', () => {
        expect(controller).toBeDefined();
    });
});
