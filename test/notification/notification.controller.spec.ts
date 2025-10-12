import { Test, TestingModule } from '@nestjs/testing';
import { NotificationController } from '../../src/notification/notification.controller';
import { NotificationService } from '../../src/notification/notification.service';

describe('NotificationController', () => {
    let controller: NotificationController;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            controllers: [NotificationController],
            providers: [NotificationService],
        }).compile();

        controller = module.get<NotificationController>(NotificationController);
    });

    it('should be defined', () => {
        expect(controller).toBeDefined();
    });
});
