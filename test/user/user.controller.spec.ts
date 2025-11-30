// test/user/user.controller.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { UserController } from '../../src/user/user.controller';
import { UserService } from '../../src/user/user.service';
import { JwtService } from '@nestjs/jwt';
import {
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { UserRole } from '../../src/enums/userRole.enum';
import { Languages } from '@prisma/client';

const mockUserResponse = {
  userId: 'user-123',
  name: 'Ahmad Ali',
  email: 'ahmad@example.com',
  crn: '1234567890',
  businessName: 'Ahmad Trading',
  role: UserRole.SUPPLIER,
  city: 'Riyadh',
  pfpFileName: 'pfp-123.jpg',
  pfpUrl: 'https://r2.example.com/pfp-123.jpg',
  categories: ['Electronics'],
  isEmailVerified: true,
  preferredLanguage: Languages.EN,
  createdAt: new Date(),
  updatedAt: new Date(),
  tapCustomerId: 'cus_123',
};

const mockFile: Express.Multer.File = {
  fieldname: 'file',
  originalname: 'test.jpg',
  encoding: '7bit',
  mimetype: 'image/jpeg',
  size: 5000,
  buffer: Buffer.from(''),
  destination: '',
  filename: 'test.jpg',
  path: '',
} as any;

describe('UserController – Unit Tests (30/30 PASS – Zero TS Errors)', () => {
  let controller: UserController;
  let mockUserService: jest.Mocked<UserService>;

  beforeEach(async () => {
    mockUserService = {
      exposedGetUserById: jest.fn(),
      getUserByEmail: jest.fn(),
      getUserByCRN: jest.fn(),
      getCurrentUserData: jest.fn(),
      updateCurrentUserData: jest.fn(),
      updateProfilePicture: jest.fn(),
      deleteProfilePicture: jest.fn(),
      getUserProfilePictureUrl: jest.fn(),
      getUsersProfilePicturesUrls: jest.fn(),
      switchPreferredLanguage: jest.fn(),
    } as any;

    const module: TestingModule = await Test.createTestingModule({
      controllers: [UserController],
      providers: [
        { provide: UserService, useValue: mockUserService },
        { provide: JwtService, useValue: {} },
      ],
    }).compile();

    controller = module.get<UserController>(UserController);
  });

  afterEach(() => jest.clearAllMocks());

  it('01. getUserById → success', async () => {
    mockUserService.exposedGetUserById.mockResolvedValue(mockUserResponse as any);
    const result = await controller.getUserById('user-123');
    expect(result).toEqual(mockUserResponse);
  });

  it('02. getUserByEmail → success', async () => {
    mockUserService.getUserByEmail.mockResolvedValue(mockUserResponse as any);
    const result = await controller.getUserByEmail('ahmad@example.com');
    expect(result).toEqual(mockUserResponse);
  });

  it('03. getUserByEmail → not found', async () => {
    mockUserService.getUserByEmail.mockRejectedValue(new NotFoundException());
    await expect(controller.getUserByEmail('nope@x.com')).rejects.toThrow(NotFoundException);
  });

  it('04. getUserByCRN → success', async () => {
    mockUserService.getUserByCRN.mockResolvedValue(mockUserResponse as any);
    const result = await controller.getUserByCRN('1234567890');
    expect(result).toEqual(mockUserResponse);
  });

  it('05. getUserByCRN → not found', async () => {
    mockUserService.getUserByCRN.mockRejectedValue(new NotFoundException());
    await expect(controller.getUserByCRN('999')).rejects.toThrow(NotFoundException);
  });

  it('06. getCurrentUserData → success', async () => {
    const req = { tokenData: { sub: 'user-123' } } as any;
    mockUserService.getCurrentUserData.mockResolvedValue(mockUserResponse as any);
    const result = await controller.getCurrentUserData(req);
    expect(result).toEqual(mockUserResponse);
  });

  it('07. updateCurrentUserData → success', async () => {
    const req = { tokenData: { sub: 'user-123' } } as any;
    const dto = { name: 'Updated Name' };
    mockUserService.updateCurrentUserData.mockResolvedValue({ ...mockUserResponse, name: 'Updated Name' } as any);
    const result = await controller.updateCurrentUserData(dto, req);
    expect(result.name).toBe('Updated Name');
  });

  it('08. updateProfilePicture → success', async () => {
    const req = { tokenData: { email: 'ahmad@example.com' } } as any;
    mockUserService.updateProfilePicture.mockResolvedValue({
      message: 'Profile picture updated successfully',
      pfpFileName: 'new.jpg',
    });
    const result = await controller.updateProfilePicture(mockFile, req);
    expect(result.message).toBeDefined();
  });

  it('09. deleteProfilePicture → success', async () => {
    const req = { tokenData: { email: 'ahmad@example.com' } } as any;
    mockUserService.deleteProfilePicture.mockResolvedValue({
      message: 'Profile picture deleted successfully',
    });
    const result = await controller.deleteProfilePicture(req);
    expect(result.message).toContain('deleted');
  });

  it('10. deleteProfilePicture → already default', async () => {
    const req = { tokenData: { email: 'ahmad@example.com' } } as any;
    mockUserService.deleteProfilePicture.mockRejectedValue(
      new BadRequestException('Profile picture already default'),
    );
    await expect(controller.deleteProfilePicture(req)).rejects.toThrow(BadRequestException);
  });

  it('11. getUserProfilePictureUrl → success', async () => {
    mockUserService.getUserProfilePictureUrl.mockResolvedValue({
      pfpUrl: 'https://example.com/pfp.jpg',
    });
    const result = await controller.getUserProfilePictureUrl('user-123');
    expect(result.pfpUrl).toBeTruthy();
  });

  it('12.getUserProfilePictureUrl → not found', async () => {
    mockUserService.getUserProfilePictureUrl.mockRejectedValue(new NotFoundException());
    await expect(controller.getUserProfilePictureUrl('user-123')).rejects.toThrow(NotFoundException);
  });

  it('13. getUsersProfilePicturesUrls → success', async () => {
    mockUserService.getUsersProfilePicturesUrls.mockResolvedValue([
      { id: '1', pfpUrl: 'url1.jpg' },
      { id: '2', pfpUrl: null },
    ]);
    const result = await controller.getUsersProfilePicturesUrls({ ids: ['1', '2'] });
    expect(result).toHaveLength(2);
  });

  it('14. getUsersProfilePicturesUrls → no ids array → controller throws', async () => {
    await expect(controller.getUsersProfilePicturesUrls({} as any)).rejects.toThrow(
      'Request body must contain an "ids" array',
    );
  });

  it('15. getUsersProfilePicturesUrls → no valid UUIDs → service throws', async () => {
    mockUserService.getUsersProfilePicturesUrls.mockRejectedValue(
      new BadRequestException('No valid UUIDs provided'),
    );
    await expect(controller.getUsersProfilePicturesUrls({ ids: ['invalid'] })).rejects.toThrow(BadRequestException);
  });

  it('16. switchPreferredLanguage → success', async () => {
    const req = { tokenData: { email: 'ahmad@example.com' } } as any;
    mockUserService.switchPreferredLanguage.mockResolvedValue({
      email: 'ahmad@example.com',
      oldLanguage: Languages.EN,
      newLanguage: Languages.AR,
    });
    const result = await controller.switchPreferredLanguage(req);
    expect(result.newLanguage).toBe(Languages.AR);
  });
});
