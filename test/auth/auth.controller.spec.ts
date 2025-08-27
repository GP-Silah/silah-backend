import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from '../../src/auth/auth.controller';
import { AuthService } from '../../src/auth/auth.service';
import { Response } from 'express';
import { SignupDto } from 'src/auth/dtos/signup.dto';
import { LoginDto } from 'src/auth/dtos/login.dto';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';

describe('AuthController', () => {
    let controller: AuthController;
    let authService: AuthService;

    // mock Response object
    const mockResponse = () => {
        const res: Partial<Response> = {};
        res.cookie = jest.fn().mockReturnValue(res);
        res.clearCookie = jest.fn().mockReturnValue(res);
        res.send = jest.fn().mockReturnValue(res);
        return res as Response;
    };

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            controllers: [AuthController],
            providers: [
                {
                    provide: AuthService,
                    useValue: {
                        signUp: jest.fn(),
                        login: jest.fn(),
                        verifyEmail: jest.fn(),
                        resendVerificationEmail: jest.fn(),
                        requestPasswordReset: jest.fn(),
                        resetPassword: jest.fn(),
                        switchUserRole: jest.fn(),
                    },
                },
            ],
        })
            .overrideGuard(JwtAuthGuard) // bypass actual JWT validation
            .useValue({
                canActivate: jest.fn().mockImplementation((context) => {
                    const req = context.switchToHttp().getRequest();
                    req.user = { id: 'test-user-id', email: 'test@test.com' };
                    return true;
                }),
            })
            .compile();

        controller = module.get<AuthController>(AuthController);
        authService = module.get<AuthService>(AuthService);
    });

    it('should be defined', () => {
        expect(controller).toBeDefined();
    });

    describe('signUp', () => {
        it('should call authService.signUp and set cookie', async () => {
            const dto = {
                email: 'test@test.com',
                password: '123456',
            } as SignupDto;
            const res = mockResponse();
            (authService.signUp as jest.Mock).mockResolvedValue('fakeToken');

            const result = await controller.signUp(dto, res);

            expect(authService.signUp).toHaveBeenCalledWith(dto);
            expect(res.cookie).toHaveBeenCalledWith('token', 'fakeToken', {
                httpOnly: true,
                secure: false, // because in test NODE_ENV !== 'production'
                sameSite: 'lax',
                path: '/',
            });
            expect(result).toEqual({ message: 'Signup successful' });
        });
    });

    describe('login', () => {
        it('should call authService.login and set cookie', async () => {
            const dto = {
                email: 'test@test.com',
                password: '123456',
            } as LoginDto;
            const res = mockResponse();
            (authService.login as jest.Mock).mockResolvedValue('fakeToken');

            const result = await controller.login(dto, res);

            expect(authService.login).toHaveBeenCalledWith(dto);
            expect(res.cookie).toHaveBeenCalled();
            expect(result).toEqual({ message: 'Login successful' });
        });
    });

    describe('logout', () => {
        it('should clear token cookie and send message', () => {
            const res = mockResponse();

            controller.logout(res);

            expect(res.clearCookie).toHaveBeenCalledWith('token');
            expect(res.send).toHaveBeenCalledWith('Successfully logged out');
        });
    });

    describe('verifyEmail', () => {
        it('should call authService.verifyEmail', async () => {
            (authService.verifyEmail as jest.Mock).mockResolvedValue(
                'verified',
            );

            const result = await controller.verifyEmail('token123');

            expect(authService.verifyEmail).toHaveBeenCalledWith('token123');
            expect(result).toBe('verified');
        });
    });

    describe('resendVerificationEmail', () => {
        it('should call authService.resendVerificationEmail', async () => {
            (
                authService.resendVerificationEmail as jest.Mock
            ).mockResolvedValue('resent');

            const result =
                await controller.resendVerificationEmail('test@test.com');

            expect(authService.resendVerificationEmail).toHaveBeenCalledWith(
                'test@test.com',
            );
            expect(result).toBe('resent');
        });
    });

    describe('requestPasswordReset', () => {
        it('should call authService.requestPasswordReset', async () => {
            (authService.requestPasswordReset as jest.Mock).mockResolvedValue(
                'resetSent',
            );

            const result =
                await controller.requestPasswordReset('test@test.com');

            expect(authService.requestPasswordReset).toHaveBeenCalledWith(
                'test@test.com',
            );
            expect(result).toBe('resetSent');
        });
    });

    describe('resetPassword', () => {
        it('should call authService.resetPassword', async () => {
            const dto = { newPassword: '123456' };
            (authService.resetPassword as jest.Mock).mockResolvedValue(
                'resetDone',
            );

            const result = await controller.resetPassword('token123', dto);

            expect(authService.resetPassword).toHaveBeenCalledWith(
                'token123',
                dto,
            );
            expect(result).toBe('resetDone');
        });
    });

    describe('switchUserRole', () => {
        it('should call authService.switchUserRole', async () => {
            const req = { user: { id: 1 } } as any;
            const res = mockResponse();
            (authService.switchUserRole as jest.Mock).mockResolvedValue(
                'roleSwitched',
            );

            const result = await controller.switchUserRole(req, res);

            expect(authService.switchUserRole).toHaveBeenCalledWith(req, res);
            expect(result).toBe('roleSwitched');
        });
    });
});
