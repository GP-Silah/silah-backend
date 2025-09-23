import { Test, TestingModule } from '@nestjs/testing';
import { CategoryController } from '../../src/category/category.controller';
import { CategoryService } from '../../src/category/category.service';

describe('CategoryController', () => {
    let controller: CategoryController;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            controllers: [CategoryController],
            providers: [CategoryService],
        }).compile();

        controller = module.get<CategoryController>(CategoryController);
    });

    it('should be defined', () => {
        expect(controller).toBeDefined();
    });
});
