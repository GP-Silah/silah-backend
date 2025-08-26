jest.mock('../../../src/logger', () => ({
    __esModule: true,
    default: {
        error: jest.fn(),
        debug: jest.fn(),
    },
}));

import { LoggerMiddleware } from '../../../src/common/middleware/logger.middleware';
import logger from '../../../src/logger';

describe('LoggerMiddleware', () => {
    let middleware: LoggerMiddleware;
    let mockRequest: any;
    let mockResponse: any;
    let nextFn: jest.Mock;

    beforeEach(() => {
        middleware = new LoggerMiddleware();
        mockRequest = { method: 'GET', originalUrl: '/test' };
        mockResponse = {};
        nextFn = jest.fn();
    });

    it('should log debug message and call next', () => {
        middleware.use(mockRequest as any, mockResponse as any, nextFn);

        expect(logger.debug).toHaveBeenCalledWith('GET /test');
        expect(nextFn).toHaveBeenCalled();
    });
});
