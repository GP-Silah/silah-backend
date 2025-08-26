import logger from '../src/logger';

describe('Logger', () => {
    it('should have debug, error methods', () => {
        expect(typeof logger.debug).toBe('function');
        expect(typeof logger.error).toBe('function');
    });

    it('should log messages without throwing', () => {
        expect(() => logger.debug('debug test')).not.toThrow();
        expect(() => logger.error('error test')).not.toThrow();
    });
});
