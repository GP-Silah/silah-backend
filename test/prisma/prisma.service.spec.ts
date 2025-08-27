import { PrismaService } from '../../src/prisma/prisma.service';

describe('PrismaService', () => {
    let prisma: PrismaService;
    let deleteManyMock: jest.Mock;
    let transactionMock: jest.Mock;

    beforeEach(() => {
        deleteManyMock = jest.fn().mockResolvedValue({ count: 0 });

        // Proxy will return { deleteMany: deleteManyMock } for any property
        const mockModels = new Proxy(
            {},
            {
                get: (_, prop) => ({ deleteMany: deleteManyMock }),
            },
        );

        transactionMock = jest
            .fn()
            .mockImplementation(async (cb) => cb(mockModels));

        prisma = new PrismaService();
        prisma.$connect = jest.fn();
        prisma.$disconnect = jest.fn();
        prisma.$transaction = transactionMock as any;

        prisma.logger = { warn: jest.fn() };
    });

    it('should connect on module init', async () => {
        await prisma.onModuleInit();
        expect(prisma.$connect).toHaveBeenCalled();
    });

    it('should disconnect on module destroy', async () => {
        await prisma.onModuleDestroy();
        expect(prisma.$disconnect).toHaveBeenCalled();
    });

    it('should clean database in test', async () => {
        process.env.NODE_ENV = 'test';
        await prisma.cleanDatabase();
        expect(deleteManyMock).toHaveBeenCalled();
        expect(prisma.logger.warn).not.toHaveBeenCalled();
    });

    it('should not clean database in production', async () => {
        process.env.NODE_ENV = 'production';
        await prisma.cleanDatabase();
        expect(deleteManyMock).not.toHaveBeenCalled();
        expect(transactionMock).not.toHaveBeenCalled();
    });
});
