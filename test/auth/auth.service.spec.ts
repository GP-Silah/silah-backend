import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from '../../src/auth/auth.service';
import { PrismaService } from '../../src/prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { UserService } from '../../src/user/user.service';
import {
    BadRequestException,
    NotFoundException,
    InternalServerErrorException,
} from '@nestjs/common';
import { SignupDto } from '../../src/auth/dtos/signup.dto';
import { LoginDto } from '../../src/auth/dtos/login.dto';
import { ResetPasswordDto } from '../../src/auth/dtos/resetPassword.dto';
import { UserRole } from '../../src/enums/userRole.enum';
import * as bcrypt from 'bcrypt';
import * as nodemailer from 'nodemailer';
import { TapPaymentsService } from 'src/tap-payments/tap-payments.service';

// Mock bcrypt
jest.mock('bcrypt');
const mockedBcrypt = bcrypt as jest.Mocked<typeof bcrypt>;

// Mock nodemailer
jest.mock('nodemailer');
const mockedNodemailer = nodemailer as jest.Mocked<typeof nodemailer>;
const mockTransporter = {
    sendMail: jest.fn(),
};
mockedNodemailer.createTransport.mockReturnValue(mockTransporter);

describe('AuthService', () => {
    let service: AuthService;
    let prismaService: any;
    let jwtService: any;
    let userService: any;
    let mockTransporter: any;
    let tapService: any;

    const mockUser = {
        id: 'user-id',
        email: 'test@example.com',
        password: 'hashedPassword',
        nid: '1234567890',
        crn: '1234567890123',
        role: UserRole.BUYER,
        isEmailVerified: false,
    };

    beforeEach(async () => {
        const mockPrismaService = {
            category: {
                findMany: jest.fn(),
            },
            user: {
                findFirst: jest.fn(),
                findUnique: jest.fn(),
                create: jest.fn(),
                update: jest.fn(),
            },
            supplier: {
                findUnique: jest.fn(),
                create: jest.fn(),
            },
        } as any;

        const mockJwtService = {
            signAsync: jest.fn(),
            verifyAsync: jest.fn(),
        } as any;

        const mockUserService = {
            generateDefaultAvatar: jest.fn(),
        } as any;

        const mockTapPaymentsService = {
            createCustomer: jest.fn().mockResolvedValue('mock-tap-customer-id'),
        };

        mockTransporter = {
            sendMail: jest.fn(),
        };

        jest.spyOn(console, 'log').mockImplementation(() => {});
        jest.spyOn(console, 'error').mockImplementation(() => {});

        mockedNodemailer.createTransport.mockReturnValue(mockTransporter);

        const module: TestingModule = await Test.createTestingModule({
            providers: [
                AuthService,
                { provide: PrismaService, useValue: mockPrismaService },
                { provide: JwtService, useValue: mockJwtService },
                { provide: UserService, useValue: mockUserService },
                {
                    provide: TapPaymentsService,
                    useValue: mockTapPaymentsService,
                },
            ],
        }).compile();

        service = module.get<AuthService>(AuthService);
        prismaService = module.get(PrismaService);
        jwtService = module.get(JwtService);
        userService = module.get(UserService);
        tapService = module.get(TapPaymentsService);
    });

    afterEach(() => {
        jest.clearAllMocks();
        jest.restoreAllMocks();
    });

    describe('encryptPassword', () => {
        it('should hash a password with default salt rounds', async () => {
            const plainText = 'password123';
            const hashedPassword = 'hashedPassword';
            mockedBcrypt.hash.mockResolvedValue(hashedPassword as never);

            const result = await service.encryptPassword(plainText);

            expect(bcrypt.hash).toHaveBeenCalledWith(plainText, 10);
            expect(result).toBe(hashedPassword);
        });

        it('should hash a password with custom salt rounds', async () => {
            const plainText = 'password123';
            const saltRounds = 12;
            const hashedPassword = 'hashedPassword';
            mockedBcrypt.hash.mockResolvedValue(hashedPassword as never);

            const result = await service.encryptPassword(plainText, saltRounds);

            expect(bcrypt.hash).toHaveBeenCalledWith(plainText, saltRounds);
            expect(result).toBe(hashedPassword);
        });
    });

    describe('signUp', () => {
        const signupDto: SignupDto = {
            email: 'test@example.com',
            password: 'password123',
            nid: '1234567890',
            crn: '1234567890123',
            categories: ['Technology', 'Healthcare'],
        } as SignupDto;

        it('should successfully register a new user', async () => {
            const mockCategories = [
                { id: 'cat1', name: 'Technology' },
                { id: 'cat2', name: 'Healthcare' },
            ];
            const hashedPassword = 'hashedPassword';
            const mockToken = 'jwt-token';
            const emailToken = 'email-token';

            prismaService.category.findMany.mockResolvedValue(mockCategories);
            prismaService.user.findFirst.mockResolvedValue(null);
            mockedBcrypt.hash.mockResolvedValue(hashedPassword as never);
            prismaService.user.create.mockResolvedValue({
                ...mockUser,
                ...signupDto,
            });
            jwtService.signAsync
                .mockResolvedValueOnce(emailToken)
                .mockResolvedValueOnce(mockToken);
            mockTransporter.sendMail.mockResolvedValue({
                response: 'Email sent',
            });

            const result = await service.signUp(signupDto);

            expect(result).toEqual({ token: mockToken });
            expect(prismaService.category.findMany).toHaveBeenCalledWith({
                where: { name: { in: signupDto.categories } },
            });
            expect(prismaService.user.findFirst).toHaveBeenCalled();
            expect(prismaService.user.create).toHaveBeenCalled();
            expect(userService.generateDefaultAvatar).toHaveBeenCalledWith(
                signupDto.email,
            );
            expect(tapService.createCustomer).toHaveBeenCalledWith({
                first_name: signupDto.name,
                email: signupDto.email,
            });
        });

        it('should throw BadRequestException for invalid categories', async () => {
            const mockCategories = [{ id: 'cat1', name: 'Technology' }]; // Missing Healthcare
            prismaService.category.findMany.mockResolvedValue(mockCategories);

            await expect(service.signUp(signupDto)).rejects.toThrow(
                new BadRequestException(
                    'These categories are invalid: Healthcare',
                ),
            );
        });

        it('should throw BadRequestException for existing NID', async () => {
            const mockCategories = [
                { id: 'cat1', name: 'Technology' },
                { id: 'cat2', name: 'Healthcare' },
            ];
            prismaService.category.findMany.mockResolvedValue(mockCategories);
            prismaService.user.findFirst.mockResolvedValue({
                ...mockUser,
                nid: signupDto.nid,
            });

            await expect(service.signUp(signupDto)).rejects.toThrow(
                new BadRequestException('NID already exists'),
            );
        });

        it('should throw BadRequestException for existing email', async () => {
            const mockCategories = [
                { id: 'cat1', name: 'Technology' },
                { id: 'cat2', name: 'Healthcare' },
            ];
            prismaService.category.findMany.mockResolvedValue(mockCategories);
            prismaService.user.findFirst.mockResolvedValue({
                ...mockUser,
                nid: 'different-nid',
                crn: 'different-crn',
                email: signupDto.email,
            });

            await expect(service.signUp(signupDto)).rejects.toThrow(
                new BadRequestException('Email already exists'),
            );
        });
    });

    describe('login', () => {
        const loginDto: LoginDto = {
            email: 'test@example.com',
            password: 'password123',
        } as LoginDto;

        it('should successfully login with email', async () => {
            const mockToken = 'jwt-token';
            prismaService.user.findFirst.mockResolvedValue(mockUser);
            mockedBcrypt.compare.mockResolvedValue(true as never);
            jwtService.signAsync.mockResolvedValue(mockToken);

            const result = await service.login(loginDto);

            expect(result).toEqual({ token: mockToken });
            expect(prismaService.user.findFirst).toHaveBeenCalledWith({
                where: {
                    OR: [{ email: loginDto.email }, { crn: loginDto.crn }],
                },
            });
            expect(bcrypt.compare).toHaveBeenCalledWith(
                loginDto.password,
                mockUser.password,
            );
        });

        it('should throw BadRequestException for non-existent user', async () => {
            prismaService.user.findFirst.mockResolvedValue(null);

            await expect(service.login(loginDto)).rejects.toThrow(
                new BadRequestException('User not found'),
            );
        });

        it('should throw BadRequestException for invalid password', async () => {
            prismaService.user.findFirst.mockResolvedValue(mockUser);
            mockedBcrypt.compare.mockResolvedValue(false as never);

            await expect(service.login(loginDto)).rejects.toThrow(
                new BadRequestException('Invalid credentials'),
            );
        });
    });

    describe('verifyEmail', () => {
        const mockToken = 'email-verification-token';
        const mockDecodedToken = { sub: 'user-id', email: 'test@example.com' };

        it('should successfully verify email', async () => {
            jwtService.verifyAsync.mockResolvedValue(mockDecodedToken);
            prismaService.user.findUnique.mockResolvedValue({
                ...mockUser,
                isEmailVerified: false,
            });
            prismaService.user.update.mockResolvedValue({
                ...mockUser,
                isEmailVerified: true,
            });

            const result = await service.verifyEmail(mockToken);

            expect(result).toEqual({ message: 'Email verified successfully' });
            expect(jwtService.verifyAsync).toHaveBeenCalledWith(mockToken);
            expect(prismaService.user.update).toHaveBeenCalledWith({
                where: { id: mockDecodedToken.sub },
                data: { isEmailVerified: true },
            });
        });

        it('should throw BadRequestException for invalid token', async () => {
            jwtService.verifyAsync.mockRejectedValue(
                new Error('Invalid token'),
            );

            await expect(service.verifyEmail(mockToken)).rejects.toThrow(
                new BadRequestException(
                    'Invalid or expired verification token',
                ),
            );
        });

        it('should throw BadRequestException for already verified user', async () => {
            jwtService.verifyAsync.mockResolvedValue(mockDecodedToken);
            prismaService.user.findUnique.mockResolvedValue({
                ...mockUser,
                isEmailVerified: true,
            });

            await expect(service.verifyEmail(mockToken)).rejects.toThrow(
                new BadRequestException('User not found or already verified'),
            );
        });
    });

    describe('resetPassword', () => {
        const resetToken = 'reset-token';
        const resetPasswordDto: ResetPasswordDto = {
            newPassword: 'newPassword123',
        };
        const mockDecodedToken = { sub: 'user-id' };

        it('should successfully reset password', async () => {
            const hashedPassword = 'newHashedPassword';
            jwtService.verifyAsync.mockResolvedValue(mockDecodedToken);
            prismaService.user.findUnique.mockResolvedValue(mockUser);
            mockedBcrypt.hash.mockResolvedValue(hashedPassword as never);
            prismaService.user.update.mockResolvedValue({
                ...mockUser,
                password: hashedPassword,
            });

            const result = await service.resetPassword(
                resetToken,
                resetPasswordDto,
            );

            expect(result).toEqual({ message: 'Password reset successfully' });
            expect(jwtService.verifyAsync).toHaveBeenCalledWith(resetToken);
            expect(prismaService.user.update).toHaveBeenCalledWith({
                where: { id: mockUser.id },
                data: { password: hashedPassword },
            });
        });

        it('should throw BadRequestException for invalid token', async () => {
            jwtService.verifyAsync.mockRejectedValue(
                new Error('Invalid token'),
            );

            await expect(
                service.resetPassword(resetToken, resetPasswordDto),
            ).rejects.toThrow(
                new BadRequestException(
                    'Invalid or expired reset password token',
                ),
            );
        });

        it('should throw NotFoundException for non-existent user', async () => {
            jwtService.verifyAsync.mockResolvedValue(mockDecodedToken);
            prismaService.user.findUnique.mockResolvedValue(null);

            await expect(
                service.resetPassword(resetToken, resetPasswordDto),
            ).rejects.toThrow(new NotFoundException('User not found'));
        });
    });

    describe('requestPasswordReset', () => {
        it('should send reset email for verified user', async () => {
            const email = 'test@example.com';
            const resetToken = 'reset-token';
            prismaService.user.findUnique.mockResolvedValue({
                ...mockUser,
                isEmailVerified: true,
            });
            jwtService.signAsync.mockResolvedValue(resetToken);
            mockTransporter.sendMail.mockResolvedValue({
                response: 'Email sent',
            });

            const result = await service.requestPasswordReset(email);

            expect(result).toEqual({
                message: 'Password reset email sent successfully',
            });
            expect(jwtService.signAsync).toHaveBeenCalledWith(
                expect.objectContaining({
                    sub: mockUser.id,
                    email: mockUser.email,
                }),
                { expiresIn: '5m' },
            );
        });

        it('should return silently for non-existent user', async () => {
            const email = 'nonexistent@example.com';
            prismaService.user.findUnique.mockResolvedValue(null);

            const result = await service.requestPasswordReset(email);

            expect(result).toBeUndefined();
            expect(jwtService.signAsync).not.toHaveBeenCalled();
        });

        it('should return silently for unverified user', async () => {
            const email = 'test@example.com';
            prismaService.user.findUnique.mockResolvedValue({
                ...mockUser,
                isEmailVerified: false,
            });

            const result = await service.requestPasswordReset(email);

            expect(result).toBeUndefined();
            expect(jwtService.signAsync).not.toHaveBeenCalled();
        });
    });

    describe('resendVerificationEmail', () => {
        it('should resend verification email for unverified user', async () => {
            const email = 'test@example.com';
            const emailToken = 'email-token';
            prismaService.user.findUnique.mockResolvedValue({
                ...mockUser,
                isEmailVerified: false,
            });
            jwtService.signAsync.mockResolvedValue(emailToken);
            mockTransporter.sendMail.mockResolvedValue({
                response: 'Email sent',
            });

            const result = await service.resendVerificationEmail(email);

            expect(result).toEqual({
                message: 'Verification email resent successfully',
            });
            expect(jwtService.signAsync).toHaveBeenCalled();
        });

        it('should throw NotFoundException for non-existent user', async () => {
            const email = 'nonexistent@example.com';
            prismaService.user.findUnique.mockResolvedValue(null);

            await expect(
                service.resendVerificationEmail(email),
            ).rejects.toThrow(new NotFoundException('User not found'));
        });

        it('should throw BadRequestException for already verified user', async () => {
            const email = 'test@example.com';
            prismaService.user.findUnique.mockResolvedValue({
                ...mockUser,
                isEmailVerified: true,
            });

            await expect(
                service.resendVerificationEmail(email),
            ).rejects.toThrow(
                new BadRequestException('Email already verified'),
            );
        });
    });

    describe('switchUserRole', () => {
        it('should switch from BUYER to SUPPLIER and create supplier record', async () => {
            const mockRequest = {
                tokenData: {
                    sub: 'user-id',
                    email: 'test@example.com',
                    role: UserRole.BUYER,
                },
            } as any;

            const mockResponse = {
                cookie: jest.fn(),
            } as any;

            const newToken = 'new-jwt-token';

            prismaService.supplier.findUnique.mockResolvedValue(null);
            prismaService.supplier.create.mockResolvedValue({
                userId: 'user-id',
            });
            prismaService.user.update.mockResolvedValue({
                ...mockUser,
                role: UserRole.SUPPLIER,
            });
            jwtService.signAsync.mockResolvedValue(newToken);

            const result = await service.switchUserRole(
                mockRequest,
                mockResponse,
            );

            expect(result).toEqual({
                message: 'Role switched successfully',
                newRole: UserRole.SUPPLIER,
            });
            expect(prismaService.supplier.create).toHaveBeenCalledWith({
                data: { userId: 'user-id' },
            });
            expect(mockResponse.cookie).toHaveBeenCalledWith(
                'token',
                newToken,
                { httpOnly: true },
            );
        });

        it('should switch from SUPPLIER to BUYER', async () => {
            const mockRequest = {
                tokenData: {
                    sub: 'user-id',
                    email: 'test@example.com',
                    role: UserRole.SUPPLIER,
                },
            } as any;

            const mockResponse = {
                cookie: jest.fn(),
            } as any;

            const newToken = 'new-jwt-token';

            prismaService.user.update.mockResolvedValue({
                ...mockUser,
                role: UserRole.BUYER,
            });
            jwtService.signAsync.mockResolvedValue(newToken);

            const result = await service.switchUserRole(
                mockRequest,
                mockResponse,
            );

            expect(result).toEqual({
                message: 'Role switched successfully',
                newRole: UserRole.BUYER,
            });
            expect(prismaService.supplier.findUnique).not.toHaveBeenCalled();
            expect(mockResponse.cookie).toHaveBeenCalledWith(
                'token',
                newToken,
                { httpOnly: true },
            );
        });

        it('should throw InternalServerErrorException for GUEST role', async () => {
            const mockRequest = {
                tokenData: {
                    sub: 'user-id',
                    email: 'test@example.com',
                    role: UserRole.GUEST,
                },
            } as any;

            const mockResponse = {
                cookie: jest.fn(),
            } as any;

            await expect(
                service.switchUserRole(mockRequest, mockResponse),
            ).rejects.toThrow(
                new InternalServerErrorException(
                    'Unexpected role: GUEST should never reach this endpoint',
                ),
            );
        });
    });

    describe('sendVerificationEmail', () => {
        it('should send verification email successfully', async () => {
            const email = 'test@example.com';
            const token = 'email-token';
            mockTransporter.sendMail.mockResolvedValue({
                response: 'Email sent',
            });

            // This method doesn't return anything, so we just ensure it doesn't throw
            await expect(
                service.sendVerificationEmail(email, token),
            ).resolves.toBeUndefined();
            expect(mockTransporter.sendMail).toHaveBeenCalled();
        });

        it('should throw InternalServerErrorException on email send failure', async () => {
            const email = 'test@example.com';
            const token = 'email-token';
            mockTransporter.sendMail.mockRejectedValue(new Error('SMTP Error'));

            await expect(
                service.sendVerificationEmail(email, token),
            ).rejects.toThrow(
                new InternalServerErrorException(
                    'Failed to send verification email',
                ),
            );
        });
    });

    describe('generateEmailVerificationToken', () => {
        it('should generate email verification token', async () => {
            const id = 'user-id';
            const email = 'test@example.com';
            const expectedToken = 'email-verification-token';
            jwtService.signAsync.mockResolvedValue(expectedToken);

            const result = await service.generateEmailVerificationToken(
                id,
                email,
            );

            expect(result).toBe(expectedToken);
            expect(jwtService.signAsync).toHaveBeenCalledWith(
                expect.objectContaining({ sub: id, email }),
            );
        });
    });
});
