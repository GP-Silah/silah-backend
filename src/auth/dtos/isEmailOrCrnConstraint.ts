import {
    ValidatorConstraint,
    ValidatorConstraintInterface,
    ValidationArguments,
} from 'class-validator';

@ValidatorConstraint({ name: 'IsEmailOrCrn', async: false })
export class IsEmailOrCrnConstraint implements ValidatorConstraintInterface {
    validate(_: any, args: ValidationArguments) {
        const obj = args.object as any;
        const hasEmail = !!obj.email;
        const hasCrn = !!obj.crn;

        // Exactly one of the two must be provided
        return (hasEmail || hasCrn) && !(hasEmail && hasCrn);
    }

    defaultMessage(args: ValidationArguments) {
        return 'Provide either email or CRN, but not both.';
    }
}
