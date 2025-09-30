import {
    registerDecorator,
    ValidationOptions,
    ValidationArguments,
} from 'class-validator';

export function IsMultipleOfCaseQuantity(
    validationOptions?: ValidationOptions,
) {
    return function (object: Object, propertyName: string) {
        registerDecorator({
            name: 'isMultipleOfCaseQuantity',
            target: object.constructor,
            propertyName: propertyName,
            options: validationOptions,
            validator: {
                validate(value: any, args: ValidationArguments) {
                    const caseQuantity = (args.object as any).caseQuantity ?? 1;
                    if (value === null || value === undefined) return true; // skip if not provided
                    return value % caseQuantity === 0;
                },
                defaultMessage(args: ValidationArguments) {
                    const caseQuantity = (args.object as any).caseQuantity ?? 1;
                    return `${args.property} must be a multiple of caseQuantity (${caseQuantity})`;
                },
            },
        });
    };
}
