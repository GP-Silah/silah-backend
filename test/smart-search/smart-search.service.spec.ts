import { Test, TestingModule } from '@nestjs/testing';
import { SmartSearchService } from '../../src/smart-search/smart-search.service';

describe('SmartSearchService', () => {
    let service: SmartSearchService;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [SmartSearchService],
        }).compile();

        service = module.get<SmartSearchService>(SmartSearchService);
    });

    it('should be defined', () => {
        expect(service).toBeDefined();
    });
});
