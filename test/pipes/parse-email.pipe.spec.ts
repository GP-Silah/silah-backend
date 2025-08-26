import { ParseEmailPipe } from '../../src/pipes/parse-email.pipe';
import { BadRequestException } from '@nestjs/common';

describe('ParseEmailPipe', () => {
    let pipe: ParseEmailPipe;

    beforeEach(() => {
        pipe = new ParseEmailPipe();
    });

    it('should return lowercased email for valid input', () => {
        const input = 'Test@Example.COM';
        const result = pipe.transform(input);
        expect(result).toBe('test@example.com');
    });

    it('should throw BadRequestException for invalid email', () => {
        const input = 'invalid-email';
        expect(() => pipe.transform(input)).toThrow(BadRequestException);
        expect(() => pipe.transform(input)).toThrow('Invalid email format');
    });

    it('should throw BadRequestException for empty string', () => {
        expect(() => pipe.transform('')).toThrow(BadRequestException);
    });

    it('should throw BadRequestException for null/undefined', () => {
        // @ts-ignore
        expect(() => pipe.transform(null)).toThrow(BadRequestException);
        // @ts-ignore
        expect(() => pipe.transform(undefined)).toThrow(BadRequestException);
    });
});
