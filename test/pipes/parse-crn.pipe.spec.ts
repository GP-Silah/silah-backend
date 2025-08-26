import { ParseCrnPipe } from '../../src/pipes/parse-crn.pipe';
import { BadRequestException } from '@nestjs/common';

describe('ParseCrnPipe', () => {
    let pipe: ParseCrnPipe;

    beforeEach(() => {
        pipe = new ParseCrnPipe();
    });

    it('should return the CRN if it is a 10-digit number', () => {
        const input = '1234567890';
        const result = pipe.transform(input);
        expect(result).toBe(input);
    });

    it('should throw BadRequestException for CRN that is not 10 digits', () => {
        const invalidInputs = [
            '123',
            'abcdefghij',
            '12345678901',
            '12345abcde',
        ];

        invalidInputs.forEach((input) => {
            expect(() => pipe.transform(input)).toThrow(BadRequestException);
            expect(() => pipe.transform(input)).toThrow(
                'CRN must be a 10-digit number',
            );
        });
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
