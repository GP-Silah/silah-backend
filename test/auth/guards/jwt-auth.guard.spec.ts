import { JwtAuthGuard } from '../../../src/auth/guards/jwt-auth.guard';
import { JwtService } from '@nestjs/jwt';
import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Request } from 'express';

describe('JwtAuthGuard', () => {
    let guard: JwtAuthGuard;
    let jwtService: JwtService;
    let mockExecutionContext: ExecutionContext;
    let mockRequest: Partial<Request>;

    beforeEach(() => {
        jwtService = {
            verifyAsync: jest.fn(),
        } as any;

        guard = new JwtAuthGuard(jwtService);

        mockRequest = {
            cookies: {},
        };

        mockExecutionContext = {
            switchToHttp: jest.fn().mockReturnValue({
                getRequest: jest.fn().mockReturnValue(mockRequest),
            }),
        } as any;
    });

    it('should be defined', () => {
        expect(guard).toBeDefined();
    });

    it('should allow access with valid token (string format)', async () => {
        const mockPayload = { userId: 1, email: 'test@example.com' };
        mockRequest.cookies = { token: 'valid-jwt-token' };

        jest.spyOn(jwtService, 'verifyAsync').mockResolvedValue(mockPayload);

        const result = await guard.canActivate(mockExecutionContext);

        expect(result).toBe(true);
        expect(jwtService.verifyAsync).toHaveBeenCalledWith('valid-jwt-token');
        expect(mockRequest.tokenData).toEqual(mockPayload);
    });

    it('should allow access with valid token (object format)', async () => {
        const mockPayload = { userId: 1, email: 'test@example.com' };
        mockRequest.cookies = { token: { token: 'valid-jwt-token' } };

        jest.spyOn(jwtService, 'verifyAsync').mockResolvedValue(mockPayload);

        const result = await guard.canActivate(mockExecutionContext);

        expect(result).toBe(true);
        expect(jwtService.verifyAsync).toHaveBeenCalledWith('valid-jwt-token');
        expect(mockRequest.tokenData).toEqual(mockPayload);
    });

    it('should throw UnauthorizedException when no cookies exist', async () => {
        mockRequest.cookies = undefined;

        await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
            new UnauthorizedException('No token found in cookies'),
        );
    });

    it('should throw UnauthorizedException when no token cookie exists', async () => {
        mockRequest.cookies = {};

        await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
            new UnauthorizedException('No token found in cookies'),
        );
    });

    it('should throw UnauthorizedException when token is null', async () => {
        mockRequest.cookies = { token: null };

        await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
            new UnauthorizedException('No token found in cookies'),
        );
    });

    it('should throw UnauthorizedException when token object has no token property', async () => {
        mockRequest.cookies = { token: { someOtherProperty: 'value' } };

        await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
            new UnauthorizedException('No token found in cookies'),
        );
    });

    it('should throw UnauthorizedException when token is not a string (number)', async () => {
        mockRequest.cookies = { token: 123 };

        await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
            new UnauthorizedException('No token found in cookies'),
        );
    });

    it('should throw UnauthorizedException when token verification fails', async () => {
        mockRequest.cookies = { token: 'invalid-token' };

        jest.spyOn(jwtService, 'verifyAsync').mockRejectedValue(
            new Error('Token expired'),
        );

        await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
            new UnauthorizedException('Invalid or expired token'),
        );

        expect(jwtService.verifyAsync).toHaveBeenCalledWith('invalid-token');
    });

    it('should throw UnauthorizedException when token verification throws any error', async () => {
        mockRequest.cookies = { token: 'malformed-token' };

        jest.spyOn(jwtService, 'verifyAsync').mockRejectedValue(
            new Error('JsonWebTokenError'),
        );

        await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
            new UnauthorizedException('Invalid or expired token'),
        );
    });

    it('should handle empty string token', async () => {
        mockRequest.cookies = { token: '' };

        await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
            new UnauthorizedException('No token found in cookies'),
        );
    });

    it('should handle object with empty string token', async () => {
        mockRequest.cookies = { token: { token: '' } };

        await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
            new UnauthorizedException('No token found in cookies'),
        );
    });

    it('should not call verifyAsync when token is invalid format', async () => {
        mockRequest.cookies = { token: null };

        await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow();

        expect(jwtService.verifyAsync).not.toHaveBeenCalled();
    });
});
