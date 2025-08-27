jest.mock('../../../src/logger', () => ({
    __esModule: true,
    default: {
        error: jest.fn(),
        debug: jest.fn(),
    },
}));

import { HttpException } from '@nestjs/common';
import { AllExceptionsFilter } from '../../../src/common/filters/all-exceptions.filter';
import logger from '../../../src/logger';

describe('AllExceptionsFilter', () => {
    let filter: AllExceptionsFilter;
    let mockResponse: any;
    let mockRequest: any;
    let mockHost: any;

    beforeEach(() => {
        filter = new AllExceptionsFilter();

        mockResponse = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn(),
        };
        mockRequest = { method: 'GET', url: '/test' };
        mockHost = {
            switchToHttp: jest.fn().mockReturnValue({
                getResponse: () => mockResponse,
                getRequest: () => mockRequest,
            }),
        };
    });

    it('should log error and send response for HttpException', () => {
        const exception = new HttpException('Bad Request', 400);

        filter.catch(exception as any, mockHost as any);

        const logged = (logger.error as jest.Mock).mock.calls[0][0];
        expect(logged).toContain('GET /test');
        expect(logged).toContain('400');
        expect(logged).toContain('Bad Request');
        expect(mockResponse.status).toHaveBeenCalledWith(400);
        expect(mockResponse.json).toHaveBeenCalled();
    });
});
