import { IsEmailOrCrnConstraint } from '../../../src/auth/dtos/isEmailOrCrnConstraint';
import { ValidationArguments } from 'class-validator';

describe('IsEmailOrCrnConstraint', () => {
    const validator = new IsEmailOrCrnConstraint();

    const makeArgs = (obj: any): ValidationArguments => ({
        object: obj,
        property: 'test',
        constraints: [],
        value: null,
        targetName: obj.constructor?.name ?? 'unknown', // required
    });

    it('valid with only email', () => {
        expect(
            validator.validate({}, makeArgs({ email: 'test@test.com' })),
        ).toBe(true);
    });

    it('valid with only CRN', () => {
        expect(validator.validate({}, makeArgs({ crn: '1234567890' }))).toBe(
            true,
        );
    });

    it('invalid with both', () => {
        expect(
            validator.validate(
                {},
                makeArgs({ email: 'a@b.com', crn: '1234567890' }),
            ),
        ).toBe(false);
    });

    it('invalid with none', () => {
        expect(validator.validate({}, makeArgs({}))).toBe(false);
    });

    it('returns default message', () => {
        expect(validator.defaultMessage(makeArgs({}))).toBe(
            'Provide either email or CRN, but not both.',
        );
    });
});
