import { Test, TestingModule } from '@nestjs/testing';
import { SupplierController } from '../../src/supplier/supplier.controller';
import { SupplierService } from '../../src/supplier/supplier.service';

describe('SupplierController', () => {
    let controller: SupplierController;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            controllers: [SupplierController],
            providers: [SupplierService],
        }).compile();

        controller = module.get<SupplierController>(SupplierController);
    });

    it('should be defined', () => {
        expect(controller).toBeDefined();
    });
});
