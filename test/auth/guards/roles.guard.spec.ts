import { RolesGuard } from '../../../src/auth/guards/roles.guard';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { ExecutionContext, ForbiddenException } from '@nestjs/common';
import { ROLES_KEY } from '../../../src/auth/decorators/roles.decorator';
import { UserRole } from '../../../src/enums/userRole.enum';

describe('RolesGuard', () => {
    let guard: RolesGuard;
    let reflector: Reflector;
    let jwtService: JwtService;
    let mockExecutionContext: ExecutionContext;

    beforeEach(() => {
        reflector = new Reflector();
        jwtService = {
            verifyAsync: jest.fn(),
        } as any;

        guard = new RolesGuard(reflector, jwtService);

        // Mock ExecutionContext
        mockExecutionContext = {
            getHandler: jest.fn(),
            getClass: jest.fn(),
            switchToHttp: jest.fn().mockReturnValue({
                getRequest: jest.fn().mockReturnValue({
                    cookies: {
                        token: { token: 'mock-jwt-token' },
                    },
                }),
            }),
        } as any;
    });

    it('should be defined', () => {
        expect(guard).toBeDefined();
    });

    it('should allow access when no roles are required', async () => {
        // Mock no required roles
        jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(null);

        const result = await guard.canActivate(mockExecutionContext);

        expect(result).toBe(true);
    });

    it('should allow access when user has required role', async () => {
        const requiredRoles = [UserRole.BUYER];
        const mockPayload = { role: UserRole.BUYER };

        jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(
            requiredRoles,
        );
        jest.spyOn(jwtService, 'verifyAsync').mockResolvedValue(mockPayload);

        const result = await guard.canActivate(mockExecutionContext);

        expect(result).toBe(true);
        expect(reflector.getAllAndOverride).toHaveBeenCalledWith(ROLES_KEY, [
            mockExecutionContext.getHandler(),
            mockExecutionContext.getClass(),
        ]);
        expect(jwtService.verifyAsync).toHaveBeenCalledWith('mock-jwt-token');
    });

    it('should allow access when user has one of multiple required roles', async () => {
        const requiredRoles = [UserRole.BUYER, UserRole.SUPPLIER];
        const mockPayload = { role: UserRole.SUPPLIER };

        jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(
            requiredRoles,
        );
        jest.spyOn(jwtService, 'verifyAsync').mockResolvedValue(mockPayload);

        const result = await guard.canActivate(mockExecutionContext);

        expect(result).toBe(true);
    });

    it('should throw ForbiddenException when user does not have required role', async () => {
        const requiredRoles = [UserRole.BUYER];
        const mockPayload = { role: UserRole.GUEST };

        jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(
            requiredRoles,
        );
        jest.spyOn(jwtService, 'verifyAsync').mockResolvedValue(mockPayload);

        await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
            new ForbiddenException('You do not have access to this resource'),
        );
    });

    it('should throw ForbiddenException when user has no role in payload', async () => {
        const requiredRoles = [UserRole.BUYER];
        const mockPayload = {}; // No role property

        jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(
            requiredRoles,
        );
        jest.spyOn(jwtService, 'verifyAsync').mockResolvedValue(mockPayload);

        await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
            new ForbiddenException('You do not have access to this resource'),
        );
    });

    it('should handle JWT verification errors', async () => {
        const requiredRoles = [UserRole.BUYER];

        jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(
            requiredRoles,
        );
        jest.spyOn(jwtService, 'verifyAsync').mockRejectedValue(
            new Error('Invalid token'),
        );

        await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
            'Invalid token',
        );
    });

    it('should handle missing token cookie', async () => {
        const requiredRoles = [UserRole.BUYER];

        // Mock request without token cookie
        const mockContext = {
            ...mockExecutionContext,
            switchToHttp: jest.fn().mockReturnValue({
                getRequest: jest.fn().mockReturnValue({
                    cookies: {}, // No token cookie
                }),
            }),
        };

        jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(
            requiredRoles,
        );

        await expect(guard.canActivate(mockContext as any)).rejects.toThrow();
    });
});
