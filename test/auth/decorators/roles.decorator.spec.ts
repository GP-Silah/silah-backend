import { Roles, ROLES_KEY } from '../../../src/auth/decorators/roles.decorator';
import { UserRole } from '../../../src/enums/userRole.enum';
import { Reflector } from '@nestjs/core';

describe('Roles Decorator', () => {
    let reflector: Reflector;

    beforeEach(() => {
        reflector = new Reflector();
    });

    it('should set roles metadata correctly', () => {
        const roles = [UserRole.BUYER, UserRole.SUPPLIER];

        // Create a test class with the decorator
        @Roles(...roles)
        class TestClass {
            testMethod() {}
        }

        // Get the metadata using Reflector
        const metadata = reflector.get(ROLES_KEY, TestClass);

        expect(metadata).toEqual(roles);
    });

    it('should set roles metadata on methods', () => {
        const roles = [UserRole.GUEST];

        class TestClass {
            @Roles(...roles)
            testMethod() {}
        }

        const metadata = reflector.get(
            ROLES_KEY,
            TestClass.prototype.testMethod,
        );

        expect(metadata).toEqual(roles);
    });

    it('should handle single role', () => {
        const role = UserRole.BUYER;

        @Roles(role)
        class TestClass {}

        const metadata = reflector.get(ROLES_KEY, TestClass);

        expect(metadata).toEqual([role]);
    });

    it('should handle empty roles array', () => {
        @Roles()
        class TestClass {}

        const metadata = reflector.get(ROLES_KEY, TestClass);

        expect(metadata).toEqual([]);
    });
});
