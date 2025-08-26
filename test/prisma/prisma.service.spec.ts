import { PrismaService } from '../../src/prisma/prisma.service';

describe('PrismaService', () => {
    let prisma: PrismaService;

    beforeEach(() => {
        prisma = new PrismaService();
        prisma.$connect = jest.fn();
        prisma.$disconnect = jest.fn();

        jest.spyOn(prisma.user, 'deleteMany').mockResolvedValue({ count: 0 });
    });

    it('should connect on module init', async () => {
        await prisma.onModuleInit();
        expect(prisma.$connect).toHaveBeenCalled();
    });

    it('should disconnect on module destroy', async () => {
        await prisma.onModuleDestroy();
        expect(prisma.$disconnect).toHaveBeenCalled();
    });

    it('should clean database', async () => {
        process.env.NODE_ENV = 'test';
        await prisma.cleanDatabase();
        expect(prisma.user.deleteMany).toHaveBeenCalled();
    });

    it('should not clean database in production', async () => {
        process.env.NODE_ENV = 'production';
        await prisma.cleanDatabase();
        expect(prisma.user.deleteMany).not.toHaveBeenCalled();
    });
});
