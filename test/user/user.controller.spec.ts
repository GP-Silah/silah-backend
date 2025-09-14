import { Test, TestingModule } from '@nestjs/testing';
import { UserController } from '../../src/user/user.controller';
import { UserService } from '../../src/user/user.service';
import { UpdateUserDto } from '../../src/user/dtos/updateUser.dto';
import { UserResponseDTO } from '../../src/user/dtos/userResponse.dto';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import { Request } from 'express';
import { UserRole } from '../../src/enums/userRole.enum';
import { JwtService } from '@nestjs/jwt';

describe('UserController', () => {
    let controller: UserController;
    let mockUserService: Partial<jest.Mocked<UserService>>;

    const mockUserResponse: UserResponseDTO = {
        id: 'clv70z13w0000unqoj4lcr8x4',
        tapCustomerId: 'cus_1234567890',
        name: 'John Doe',
        email: 'user@example.com',
        crn: '1234567890',
        businessName: 'Acme Corp',
        role: UserRole.BUYER,
        city: 'Riyadh',
        pfpFileName: 'moon.jpeg',
        pfpUrl: 'https://example.com/moon.jpeg',
        categories: ['Home & Living', 'Technical & Repair Services'],
        isEmailVerified: true,
        createdAt: new Date('2025-07-04T07:31:00.000Z'),
        updatedAt: new Date('2025-07-05T14:48:00.000Z'),
    };

    const mockFile: Express.Multer.File = {
        fieldname: 'pfp',
        originalname: 'profile.jpg',
        encoding: '7bit',
        mimetype: 'image/jpeg',
        size: 1024,
        buffer: Buffer.from(''),
        stream: {} as any,
        destination: '/tmp',
        filename: 'profile.jpg',
        path: '/tmp/profile.jpg',
    };

    beforeEach(async () => {
        mockUserService = {
            getUserByEmail: jest.fn(),
            getUserByCRN: jest.fn(),
            getUserByName: jest.fn(),
            getCurrentUserData: jest.fn(),
            updateCurrentUserData: jest.fn(),
            updateProfilePicture: jest.fn(),
            deleteProfilePicture: jest.fn(),
            getUserProfilePictureUrl: jest.fn(),
            getUsersProfilePicturesUrls: jest.fn(),
        };

        const module: TestingModule = await Test.createTestingModule({
            controllers: [UserController],
            providers: [
                {
                    provide: UserService,
                    useValue: mockUserService,
                },
                {
                    provide: JwtService,
                    useValue: {
                        sign: jest.fn().mockReturnValue('mocked-token'),
                        verify: jest.fn().mockReturnValue({
                            sub: 'clv70z13w0000unqoj4lcr8x4',
                            email: 'user@example.com',
                        }),
                    },
                },
            ],
        })
            .overrideGuard('JwtAuthGuard') // Mock JwtAuthGuard to bypass actual JWT validation
            .useValue({
                canActivate: jest.fn().mockImplementation((context) => {
                    const request = context.switchToHttp().getRequest();
                    request.tokenData = {
                        sub: 'clv70z13w0000unqoj4lcr8x4',
                        email: 'user@example.com',
                    };
                    return true;
                }),
            })
            .compile();

        controller = module.get<UserController>(UserController);
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    describe('getUserByEmail', () => {
        it('should return user data for a valid email', async () => {
            mockUserService.getUserByEmail!.mockResolvedValue(mockUserResponse);

            const result = await controller.getUserByEmail('user@example.com');

            expect(mockUserService.getUserByEmail).toHaveBeenCalledWith(
                'user@example.com',
            );
            expect(result).toEqual(mockUserResponse);
        });

        it('should throw NotFoundException if user not found', async () => {
            mockUserService.getUserByEmail!.mockRejectedValue(
                new NotFoundException(
                    'User with email user@example.com not found',
                ),
            );

            await expect(
                controller.getUserByEmail('user@example.com'),
            ).rejects.toThrow(NotFoundException);
            expect(mockUserService.getUserByEmail).toHaveBeenCalledWith(
                'user@example.com',
            );
        });
    });

    describe('getUserByCRN', () => {
        it('should return user data for a valid CRN', async () => {
            mockUserService.getUserByCRN!.mockResolvedValue(mockUserResponse);

            const result = await controller.getUserByCRN('1234567890');

            expect(mockUserService.getUserByCRN).toHaveBeenCalledWith(
                '1234567890',
            );
            expect(result).toEqual(mockUserResponse);
        });

        it('should throw NotFoundException if user not found', async () => {
            mockUserService.getUserByCRN!.mockRejectedValue(
                new NotFoundException('User with CRN 1234567890 not found'),
            );

            await expect(controller.getUserByCRN('1234567890')).rejects.toThrow(
                NotFoundException,
            );
            expect(mockUserService.getUserByCRN).toHaveBeenCalledWith(
                '1234567890',
            );
        });
    });

    describe('getUserByName', () => {
        it('should return an array of users for a valid name', async () => {
            mockUserService.getUserByName!.mockResolvedValue([
                mockUserResponse,
            ]);

            const result = await controller.getUserByName('John');

            expect(mockUserService.getUserByName).toHaveBeenCalledWith('John');
            expect(result).toEqual([mockUserResponse]);
        });

        it('should throw NotFoundException if no users found', async () => {
            mockUserService.getUserByName!.mockRejectedValue(
                new NotFoundException('No users found matching name: John'),
            );

            await expect(controller.getUserByName('John')).rejects.toThrow(
                NotFoundException,
            );
            expect(mockUserService.getUserByName).toHaveBeenCalledWith('John');
        });
    });

    describe('getCurrentUserData', () => {
        it('should return current user data', async () => {
            const mockRequest = {
                tokenData: { sub: 'clv70z13w0000unqoj4lcr8x4' },
            } as unknown as Request;
            mockUserService.getCurrentUserData!.mockResolvedValue(
                mockUserResponse,
            );

            const result = await controller.getCurrentUserData(mockRequest);

            expect(mockUserService.getCurrentUserData).toHaveBeenCalledWith(
                'clv70z13w0000unqoj4lcr8x4',
            );
            expect(result).toEqual(mockUserResponse);
        });

        it('should throw NotFoundException if user not found', async () => {
            const mockRequest = {
                tokenData: { sub: 'clv70z13w0000unqoj4lcr8x4' },
            } as unknown as Request;
            mockUserService.getCurrentUserData!.mockRejectedValue(
                new NotFoundException('User data not found'),
            );

            await expect(
                controller.getCurrentUserData(mockRequest),
            ).rejects.toThrow(NotFoundException);
            expect(mockUserService.getCurrentUserData).toHaveBeenCalledWith(
                'clv70z13w0000unqoj4lcr8x4',
            );
        });
    });

    describe('updateCurrentUserData', () => {
        it('should update and return user data', async () => {
            const mockRequest = {
                tokenData: { sub: 'clv70z13w0000unqoj4lcr8x4' },
            } as unknown as Request;
            const updateDto: UpdateUserDto = {
                name: 'Jane Doe',
                email: 'jane@example.com',
                newPassword: 'NewPass123',
                businessName: 'Jane Corp',
                city: 'Jeddah',
                categories: ['Technical & Repair Services'],
            };
            mockUserService.updateCurrentUserData!.mockResolvedValue({
                ...mockUserResponse,
                name: 'Jane Doe',
                email: 'jane@example.com',
            });

            const result = await controller.updateCurrentUserData(
                updateDto,
                mockRequest,
            );

            expect(mockUserService.updateCurrentUserData).toHaveBeenCalledWith(
                updateDto,
                'clv70z13w0000unqoj4lcr8x4',
            );
            expect(result).toEqual({
                ...mockUserResponse,
                name: 'Jane Doe',
                email: 'jane@example.com',
            });
        });

        it('should throw NotFoundException if user not found', async () => {
            const mockRequest = {
                tokenData: { sub: 'clv70z13w0000unqoj4lcr8x4' },
            } as unknown as Request;
            const updateDto: UpdateUserDto = { name: 'Jane Doe' };
            mockUserService.updateCurrentUserData!.mockRejectedValue(
                new NotFoundException('User not found'),
            );

            await expect(
                controller.updateCurrentUserData(updateDto, mockRequest),
            ).rejects.toThrow(NotFoundException);
            expect(mockUserService.updateCurrentUserData).toHaveBeenCalledWith(
                updateDto,
                'clv70z13w0000unqoj4lcr8x4',
            );
        });
    });

    describe('updateProfilePicture', () => {
        it('should update profile picture and return success message', async () => {
            const mockRequest = {
                tokenData: { email: 'user@example.com' },
            } as unknown as Request;
            mockUserService.updateProfilePicture!.mockResolvedValue({
                message: 'Profile picture updated successfully',
                pfpFileName: 'new-profile.jpg',
            });

            const result = await controller.updateProfilePicture(
                mockFile,
                mockRequest,
            );

            expect(mockUserService.updateProfilePicture).toHaveBeenCalledWith(
                mockFile,
                'user@example.com',
            );
            expect(result).toEqual({
                message: 'Profile picture updated successfully',
                pfpFileName: 'new-profile.jpg',
            });
        });
    });

    describe('deleteProfilePicture', () => {
        it('should delete profile picture and return success message', async () => {
            const mockRequest = {
                tokenData: { email: 'user@example.com' },
            } as unknown as Request;
            mockUserService.deleteProfilePicture!.mockResolvedValue({
                message: 'Profile picture deleted successfully',
            });

            const result = await controller.deleteProfilePicture(mockRequest);

            expect(mockUserService.deleteProfilePicture).toHaveBeenCalledWith(
                'user@example.com',
            );
            expect(result).toEqual({
                message: 'Profile picture deleted successfully',
            });
        });

        it('should throw BadRequestException if profile picture is already default', async () => {
            const mockRequest = {
                tokenData: { email: 'user@example.com' },
            } as unknown as Request;
            mockUserService.deleteProfilePicture!.mockRejectedValue(
                new BadRequestException('Profile picture already default'),
            );

            await expect(
                controller.deleteProfilePicture(mockRequest),
            ).rejects.toThrow(BadRequestException);
            expect(mockUserService.deleteProfilePicture).toHaveBeenCalledWith(
                'user@example.com',
            );
        });
    });

    describe('getUserProfilePictureUrl', () => {
        it('should return profile picture URL for a valid user ID', async () => {
            mockUserService.getUserProfilePictureUrl!.mockResolvedValue({
                pfpUrl: 'https://example.com/moon.jpeg',
            });

            const result = await controller.getUserProfilePictureUrl(
                'clv70z13w0000unqoj4lcr8x4',
            );

            expect(
                mockUserService.getUserProfilePictureUrl,
            ).toHaveBeenCalledWith('clv70z13w0000unqoj4lcr8x4');
            expect(result).toEqual({ pfpUrl: 'https://example.com/moon.jpeg' });
        });

        it('should throw NotFoundException if profile picture not found', async () => {
            mockUserService.getUserProfilePictureUrl!.mockRejectedValue(
                new NotFoundException('Profile picture not found'),
            );

            await expect(
                controller.getUserProfilePictureUrl(
                    'clv70z13w0000unqoj4lcr8x4',
                ),
            ).rejects.toThrow(NotFoundException);
            expect(
                mockUserService.getUserProfilePictureUrl,
            ).toHaveBeenCalledWith('clv70z13w0000unqoj4lcr8x4');
        });
    });

    describe('getUsersProfilePicturesUrls', () => {
        it('should return profile picture URLs for valid user IDs', async () => {
            const mockIds = [
                'clv70z13w0000unqoj4lcr8x4',
                'clv70z13w0000unqoj4lcr8x5',
            ];
            mockUserService.getUsersProfilePicturesUrls!.mockResolvedValue([
                {
                    id: 'clv70z13w0000unqoj4lcr8x4',
                    pfpUrl: 'https://example.com/moon.jpeg',
                },
                { id: 'clv70z13w0000unqoj4lcr8x5', pfpUrl: null },
            ]);

            const result = await controller.getUsersProfilePicturesUrls({
                ids: mockIds,
            });

            expect(
                mockUserService.getUsersProfilePicturesUrls,
            ).toHaveBeenCalledWith(mockIds);
            expect(result).toEqual([
                {
                    id: 'clv70z13w0000unqoj4lcr8x4',
                    pfpUrl: 'https://example.com/moon.jpeg',
                },
                { id: 'clv70z13w0000unqoj4lcr8x5', pfpUrl: null },
            ]);
        });

        it('should throw BadRequestException if no valid UUIDs provided', async () => {
            mockUserService.getUsersProfilePicturesUrls!.mockRejectedValue(
                new BadRequestException('No valid UUIDs provided'),
            );

            await expect(
                controller.getUsersProfilePicturesUrls({
                    ids: ['invalid-uuid'],
                }),
            ).rejects.toThrow(BadRequestException);
            expect(
                mockUserService.getUsersProfilePicturesUrls,
            ).toHaveBeenCalledWith(['invalid-uuid']);
        });

        it('should throw NotFoundException if no users found', async () => {
            const mockIds = ['clv70z13w0000unqoj4lcr8x4'];
            mockUserService.getUsersProfilePicturesUrls!.mockRejectedValue(
                new NotFoundException('No users found with the provided IDs'),
            );

            await expect(
                controller.getUsersProfilePicturesUrls({ ids: mockIds }),
            ).rejects.toThrow(NotFoundException);
            expect(
                mockUserService.getUsersProfilePicturesUrls,
            ).toHaveBeenCalledWith(mockIds);
        });
    });
});
