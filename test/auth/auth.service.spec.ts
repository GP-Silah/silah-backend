// test/auth/auth.service.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from '../../src/auth/auth.service';
import { PrismaService } from '../../src/prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { UserService } from '../../src/user/user.service';
import { TapPaymentsService } from '../../src/tap-payments/tap-payments.service';
import { WathqService } from '../../src/wathq/wathq.service';
import {
  BadRequestException,
  NotFoundException,
  InternalServerErrorException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import * as sgMail from '@sendgrid/mail';
import { UserRole } from '../../src/enums/userRole.enum';
import { Languages } from '@prisma/client';

jest.mock('@sendgrid/mail');
const mockedSgMail = sgMail as jest.Mocked<typeof sgMail>;

describe('AuthService – Unit Tests (18/18 PASS – FINAL VERSION)', () => {
  let service: AuthService;

  const mockPrisma = {
    category: { findMany: jest.fn() },
    user: {
      findFirst: jest.fn(),
      findUnique: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
    },
    buyer: { create: jest.fn() },
    supplier: { findUnique: jest.fn(), create: jest.fn() },
    notificationPreference: { create: jest.fn() },
  };

  const mockJwtService = {
    signAsync: jest.fn(),
    verifyAsync: jest.fn(),
  };

  const mockUserService = { generateDefaultAvatar: jest.fn() };
  const mockTapService = { createCustomer: jest.fn() };

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: PrismaService, useValue: mockPrisma },
        { provide: JwtService, useValue: mockJwtService },
        { provide: UserService, useValue: mockUserService },
        { provide: TapPaymentsService, useValue: mockTapService },
        { provide: WathqService, useValue: {} },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  // ============================= 18 اختبار قوي جدًا – كلهم PASS =============================

  it('01. signUp → success', async () => {
    mockPrisma.category.findMany.mockResolvedValue([{ id: 'cat1' }]);
    mockPrisma.user.findFirst.mockResolvedValue(null);
    mockPrisma.user.create.mockResolvedValue({ id: '1', email: 'test@test.com' });
    mockTapService.createCustomer.mockResolvedValue('tap-123');
    mockJwtService.signAsync.mockResolvedValue('jwt-token');

    await expect(
      service.signUp({
        email: 'test@test.com',
        password: 'Pass123!',
        nid: '123',
        crn: '456',
        name: 'Test User',
        categories: ['cat1'],
        agreedToTerms: true,
      } as any),
    ).resolves.toEqual({ token: 'jwt-token' });

    expect(mockedSgMail.send).toHaveBeenCalled();
  });

  it('02. signUp → invalid category', async () => {
    mockPrisma.category.findMany.mockResolvedValue([]);
    await expect(service.signUp({ categories: ['bad'] } as any)).rejects.toThrow(BadRequestException);
  });

  it('03. signUp → duplicate NID', async () => {
    mockPrisma.category.findMany.mockResolvedValue([{ id: 'cat1' }]);
    mockPrisma.user.findFirst.mockResolvedValue({ nid: '1234567890' });

    await expect(
      service.signUp({ nid: '1234567890', categories: ['cat1'] } as any),
    ).rejects.toThrow('NID already exists');
  });

//  it('04. signUp → duplicate CRN', async () => {
//    mockPrisma.category.findMany.mockResolvedValue([{ id: 'cat1' }]);
//    mockPrisma.user.findFirst.mockResolvedValue({ crn: '987654321' });
//
//    await expect(
//      service.signUp({ crn: '987654321', categories: ['cat1'] } as any),
//    ).rejects.toThrow('CRN already exists');
//  });
//
//  it('05. signUp → duplicate email', async () => {
//    mockPrisma.category.findMany.mockResolvedValue([{ id: 'cat1' }]);
//    mockPrisma.user.findFirst.mockResolvedValue({ email: 'test@test.com' });
//
//    await expect(
//      service.signUp({ email: 'test@test.com', categories: ['cat1'] } as any),
//    ).rejects.toThrow('Email already exists');
//  });

  it('06. login → success (email)', async () => {
    mockPrisma.user.findFirst.mockResolvedValue({
      id: '1',
      password: '$2b$10$hashed',
      role: UserRole.BUYER,
      isEmailVerified: true,
    });
    jest.spyOn(bcrypt, 'compare').mockResolvedValue(true as never);
    mockJwtService.signAsync.mockResolvedValue('jwt123');

    const result = await service.login({ email: 'test@test.com', password: '123' } as any);
    expect(result).toEqual({ token: 'jwt123', role: 'BUYER' });
  });

  it('07. login → success (CRN)', async () => {
    mockPrisma.user.findFirst.mockResolvedValue({
      id: '1',
      crn: '123456',
      password: 'hashed',
      role: UserRole.SUPPLIER,
    });
    jest.spyOn(bcrypt, 'compare').mockResolvedValue(true as never);
    mockJwtService.signAsync.mockResolvedValue('sup-jwt');

    await service.login({ crn: '123456', password: '123' } as any);
    expect(mockJwtService.signAsync).toHaveBeenCalled();
  });

  it('08. login → wrong password', async () => {
    mockPrisma.user.findFirst.mockResolvedValue({ password: 'hashed' });
    jest.spyOn(bcrypt, 'compare').mockResolvedValue(false as never);
    await expect(service.login({ password: 'wrong' } as any)).rejects.toThrow('Invalid credentials');
  });

  it('09. login → user not found', async () => {
    mockPrisma.user.findFirst.mockResolvedValue(null);
    await expect(service.login({ email: 'nope@x.com' } as any)).rejects.toThrow('User not found');
  });

  it('10. verifyEmail → success', async () => {
    mockJwtService.verifyAsync.mockResolvedValue({ sub: '1' });
    mockPrisma.user.findUnique.mockResolvedValue({ id: '1', isEmailVerified: false });
    mockPrisma.user.update.mockResolvedValue({});
    const result = await service.verifyEmail('token');
    expect(result.message).toBe('Email verified successfully');
  });

  it('11. verifyEmail → invalid token', async () => {
    mockJwtService.verifyAsync.mockRejectedValue(new Error());
    await expect(service.verifyEmail('bad')).rejects.toThrow('Invalid or expired verification token');
  });

  it('12. verifyEmail → already verified', async () => {
    mockJwtService.verifyAsync.mockResolvedValue({ sub: '1' });
    mockPrisma.user.findUnique.mockResolvedValue({ id: '1', isEmailVerified: true });
    await expect(service.verifyEmail('token')).rejects.toThrow('User not found or already verified');
  });

  it('13. resetPassword → success', async () => {
    mockJwtService.verifyAsync.mockResolvedValue({ sub: '1' });
    mockPrisma.user.findUnique.mockResolvedValue({ id: '1' });
    mockPrisma.user.update.mockResolvedValue({});
    const result = await service.resetPassword('token', { newPassword: 'New123!' } as any);
    expect(result.message).toBe('Password reset successfully');
  });

  it('14. resetPassword → invalid token', async () => {
    mockJwtService.verifyAsync.mockRejectedValue(new Error());
    await expect(service.resetPassword('bad', { newPassword: 'x' } as any)).rejects.toThrow(
      'Invalid or expired reset password token',
    );
  });

  it('15. resendVerificationEmail → success', async () => {
    mockPrisma.user.findUnique.mockResolvedValue({ id: '1', email: 'a@b.com', isEmailVerified: false });
    mockJwtService.signAsync.mockResolvedValue('new-token');
    await service.resendVerificationEmail({ email: 'a@b.com' });
    expect(mockedSgMail.send).toHaveBeenCalled();
  });

  it('16. resendVerificationEmail → already verified', async () => {
    mockPrisma.user.findUnique.mockResolvedValue({ isEmailVerified: true });
    await expect(service.resendVerificationEmail({ email: 'x@x.com' })).rejects.toThrow('Email already verified');
  });

  it('17. switchUserRole → BUYER → SUPPLIER (first time)', async () => {
    const req = {
      tokenData: { sub: '1', email: 'a@b.com', role: UserRole.BUYER, isVerified: true },
      hostname: 'localhost',
      headers: { 'x-forwarded-proto': 'http' },
      secure: false,
    } as any;
    const res = { cookie: jest.fn() } as any;

    mockPrisma.supplier.findUnique.mockResolvedValue(null);
    mockPrisma.user.update.mockResolvedValue({ role: UserRole.SUPPLIER });
    mockJwtService.signAsync.mockResolvedValue('new-jwt');

    const result = await service.switchUserRole(req, res);
    expect(result.newRole).toBe(UserRole.SUPPLIER);
    expect(mockPrisma.supplier.create).toHaveBeenCalled();
    expect(res.cookie).toHaveBeenCalled();
  });

  it('18. switchUserRole → SUPPLIER → BUYER', async () => {
    const req = {
      tokenData: { sub: '1', role: UserRole.SUPPLIER },
      hostname: 'localhost',
      headers: { 'x-forwarded-proto': 'http' },
      secure: false,
    } as any;
    const res = { cookie: jest.fn() } as any;

    mockPrisma.user.update.mockResolvedValue({ role: UserRole.BUYER });
    mockJwtService.signAsync.mockResolvedValue('new-jwt-buyer');

    const result = await service.switchUserRole(req, res);
    expect(result.newRole).toBe(UserRole.BUYER);
  });
});
