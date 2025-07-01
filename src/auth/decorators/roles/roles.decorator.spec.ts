import { Roles, ROLES_KEY } from './roles.decorator';
import { UserRole } from '../../../enums/userRole';

describe('Roles Decorator', () => {
  it('should return the correct metadata', () => {
    const roles = [UserRole.BUYER, UserRole.SUPPLIER];
    const result = Roles(...roles);

    // The decorator returns a function which sets metadata,
    // but we can check what metadata it sets with Reflect
    const mockTarget = {};
    const mockKey = 'testMethod';

    // Apply the decorator function to the mock target
    result(
      mockTarget,
      mockKey,
      Object.getOwnPropertyDescriptor(mockTarget, mockKey) || {},
    );

    // Retrieve the metadata set by the decorator
    const metadata = Reflect.getMetadata(ROLES_KEY, mockTarget, mockKey);

    expect(metadata).toEqual(roles);
  });
});
