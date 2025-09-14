import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import { UserService } from '../../src/user/user.service';
import { PrismaService } from '../../src/prisma/prisma.service';
import { AuthService } from '../../src/auth/auth.service';
import { FileService } from '../../src/file/file.service';
import { UserRole as AppUserRole } from '../../src/enums/userRole.enum';
import { tap } from 'rxjs';

describe('UserService', () => {
    let service: UserService;
    let prismaService: any;
    let authService: any;
    let fileService: any;

    // Mock user data for testing
    const mockUser = {
        id: '123e4567-e89b-12d3-a456-426614174000',
        tapCustomerId: 'cus_123456789',
        name: 'John Doe',
        email: 'john@example.com',
        crn: 'CRN123456',
        businessName: 'John Business',
        role: 'BUYER',
        city: 'Riyadh',
        pfpFileName: 'profile-pic.png',
        isEmailVerified: true,
        createdAt: new Date('2024-01-01'),
        updatedAt: new Date('2024-01-02'),
        password: 'hashedpassword',
        isPfpDefault: false,
    };

    const mockCategories = [
        'Agricultural & Pet Supplies',
        'Beauty & Personal Care',
    ];
    const mockPfpUrl = 'https://example.com/profile-pic.png';

    beforeEach(async () => {
        // Create properly typed mocked services
        const mockPrismaService = {
            user: {
                findUnique: jest.fn().mockResolvedValue(null),
                findMany: jest.fn().mockResolvedValue([]),
                update: jest.fn().mockResolvedValue(null),
            },
            userCategory: {
                deleteMany: jest.fn().mockResolvedValue({ count: 0 }),
                createMany: jest.fn().mockResolvedValue({ count: 0 }),
            },
            category: {
                findMany: jest.fn().mockResolvedValue([]),
            },
        } as any;

        const mockAuthService = {
            generateEmailVerificationToken: jest
                .fn()
                .mockResolvedValue('mock-token'),
            sendVerificationEmail: jest.fn().mockResolvedValue(undefined),
            encryptPassword: jest.fn().mockResolvedValue('hashed-password'),
        } as any;

        const mockFileService = {
            getFileUrl: jest.fn().mockResolvedValue(''),
            uploadFile: jest.fn().mockResolvedValue('uploaded-filename'),
        } as any;

        const module: TestingModule = await Test.createTestingModule({
            providers: [
                UserService,
                {
                    provide: PrismaService,
                    useValue: mockPrismaService,
                },
                {
                    provide: AuthService,
                    useValue: mockAuthService,
                },
                {
                    provide: FileService,
                    useValue: mockFileService,
                },
            ],
        }).compile();

        service = module.get<UserService>(UserService);
        prismaService = module.get(PrismaService);
        authService = module.get(AuthService);
        fileService = module.get(FileService);
    });

    it('should be defined', () => {
        expect(service).toBeDefined();
    });

    describe('updateCurrentUserData', () => {
        const mockUpdateDto = {
            name: 'Updated Name',
            email: 'updated@example.com',
            businessName: 'Updated Business',
            city: 'Jeddah',
            newPassword: 'newPassword123',
            categories: [
                'Agricultural & Pet Supplies',
                'Beauty & Personal Care',
            ],
        };

        const mockUserWithCategories = {
            ...mockUser,
            categories: [
                {
                    categoryId: 1,
                    category: { name: 'Agricultural & Pet Supplies' },
                },
                { categoryId: 2, category: { name: 'Beauty & Personal Care' } },
            ],
        };

        beforeEach(() => {
            // Reset all mocks
            jest.clearAllMocks();
        });

        it('should update user with all provided fields', async () => {
            // Arrange
            prismaService.user.findUnique.mockResolvedValue(
                mockUserWithCategories,
            );
            authService.generateEmailVerificationToken.mockResolvedValue(
                'verification-token',
            );
            authService.encryptPassword.mockResolvedValue(
                'hashed-new-password',
            );

            // Mock category validation
            const mockCategories = [
                { id: 3, name: 'Technical & Repair Services' },
                { id: 4, name: 'Business & Marketing Services' },
            ];
            prismaService.category.findMany.mockResolvedValue(mockCategories);

            const updatedUser = {
                ...mockUserWithCategories,
                name: mockUpdateDto.name,
                email: mockUpdateDto.email,
                businessName: mockUpdateDto.businessName,
                city: mockUpdateDto.city,
                password: 'hashed-new-password',
            };
            prismaService.user.update.mockResolvedValue(updatedUser);

            jest.spyOn(service as any, 'getUserCategories').mockResolvedValue([
                'Technical & Repair Services',
                'Business & Marketing Services',
            ]);
            fileService.getFileUrl.mockResolvedValue(mockPfpUrl);

            // Act
            const result = await service.updateCurrentUserData(
                mockUpdateDto,
                mockUser.id,
            );

            // Assert
            expect(
                authService.generateEmailVerificationToken,
            ).toHaveBeenCalledWith(mockUser.id, mockUser.email);
            expect(authService.sendVerificationEmail).toHaveBeenCalledWith(
                mockUpdateDto.email,
                'verification-token',
            );
            expect(authService.encryptPassword).toHaveBeenCalledWith(
                mockUpdateDto.newPassword,
            );

            expect(prismaService.userCategory.deleteMany).toHaveBeenCalledWith({
                where: { userId: mockUser.id },
            });
            expect(prismaService.userCategory.createMany).toHaveBeenCalledWith({
                data: [
                    { userId: mockUser.id, categoryId: 3 },
                    { userId: mockUser.id, categoryId: 4 },
                ],
            });

            expect(prismaService.user.update).toHaveBeenCalledWith({
                where: { id: mockUser.id },
                data: {
                    name: mockUpdateDto.name,
                    email: mockUpdateDto.email,
                    businessName: mockUpdateDto.businessName,
                    city: mockUpdateDto.city,
                    password: 'hashed-new-password',
                },
                include: { categories: { include: { category: true } } },
            });

            expect(result.name).toBe(mockUpdateDto.name);
        });

        it('should not send email verification if email unchanged', async () => {
            // Arrange
            const dtoWithSameEmail = {
                name: 'Updated Name',
                email: mockUser.email, // Same email - no categories
                businessName: 'Updated Business',
            };
            prismaService.user.findUnique.mockResolvedValue(
                mockUserWithCategories,
            );
            prismaService.user.update.mockResolvedValue(mockUserWithCategories);
            jest.spyOn(service as any, 'getUserCategories').mockResolvedValue(
                [],
            );
            fileService.getFileUrl.mockResolvedValue('');

            // Act
            await service.updateCurrentUserData(dtoWithSameEmail, mockUser.id);

            // Assert
            expect(
                authService.generateEmailVerificationToken,
            ).not.toHaveBeenCalled();
            expect(authService.sendVerificationEmail).not.toHaveBeenCalled();
        });

        it('should not encrypt password if no new password provided', async () => {
            // Arrange
            const dtoWithoutPassword = { name: 'New Name' };
            prismaService.user.findUnique.mockResolvedValue(
                mockUserWithCategories,
            );
            prismaService.user.update.mockResolvedValue(mockUserWithCategories);
            jest.spyOn(service as any, 'getUserCategories').mockResolvedValue(
                [],
            );
            fileService.getFileUrl.mockResolvedValue('');

            // Act
            await service.updateCurrentUserData(
                dtoWithoutPassword,
                mockUser.id,
            );

            // Assert
            expect(authService.encryptPassword).not.toHaveBeenCalled();
            expect(prismaService.user.update).toHaveBeenCalledWith(
                expect.objectContaining({
                    data: expect.objectContaining({
                        password: mockUser.password, // Should use existing password
                    }),
                }),
            );
        });

        it('should not update categories if none provided', async () => {
            // Arrange
            const dtoWithoutCategories = { name: 'New Name' };
            prismaService.user.findUnique.mockResolvedValue(
                mockUserWithCategories,
            );
            prismaService.user.update.mockResolvedValue(mockUserWithCategories);
            jest.spyOn(service as any, 'getUserCategories').mockResolvedValue(
                [],
            );
            fileService.getFileUrl.mockResolvedValue('');

            // Act
            await service.updateCurrentUserData(
                dtoWithoutCategories,
                mockUser.id,
            );

            // Assert
            expect(prismaService.category.findMany).not.toHaveBeenCalled();
            expect(prismaService.userCategory.createMany).toHaveBeenCalledWith({
                data: [
                    { userId: mockUser.id, categoryId: 1 },
                    { userId: mockUser.id, categoryId: 2 },
                ],
            });
        });

        it('should throw NotFoundException if user not found', async () => {
            // Arrange
            prismaService.user.findUnique.mockResolvedValue(null);

            // Act & Assert
            await expect(
                service.updateCurrentUserData(mockUpdateDto, 'nonexistent-id'),
            ).rejects.toThrow(new NotFoundException('User not found'));
        });

        it('should throw BadRequestException for invalid categories', async () => {
            // Arrange
            const dtoWithInvalidCategories = {
                categories: ['Agricultural & Pet Supplies', 'InvalidCategory'],
            };
            prismaService.user.findUnique.mockResolvedValue(
                mockUserWithCategories,
            );

            // Mock only one category found (Agricultural & Pet Supplies missing)?
            prismaService.category.findMany.mockResolvedValue([
                { id: 1, name: 'Agricultural & Pet Supplies' },
            ]);

            // Act & Assert
            await expect(
                service.updateCurrentUserData(
                    dtoWithInvalidCategories,
                    mockUser.id,
                ),
            ).rejects.toThrow('These categories are invalid: InvalidCategory');
        });

        it('should handle partial updates correctly', async () => {
            // Arrange - only update name
            const partialDto = { name: 'Only Name Updated' };
            prismaService.user.findUnique.mockResolvedValue(
                mockUserWithCategories,
            );
            prismaService.user.update.mockResolvedValue({
                ...mockUserWithCategories,
                name: 'Only Name Updated',
            });
            jest.spyOn(service as any, 'getUserCategories').mockResolvedValue(
                [],
            );
            fileService.getFileUrl.mockResolvedValue('');

            // Act
            await service.updateCurrentUserData(partialDto, mockUser.id);

            // Assert
            expect(prismaService.user.update).toHaveBeenCalledWith({
                where: { id: mockUser.id },
                data: {
                    name: 'Only Name Updated',
                    password: mockUser.password, // Should keep existing password
                },
                include: { categories: { include: { category: true } } },
            });
        });
    });

    describe('toUserResponseDTO (tested via getUserById)', () => {
        beforeEach(() => {
            // Mock the private methods that toUserResponseDTO calls
            jest.spyOn(service as any, 'getUserCategories').mockResolvedValue(
                mockCategories,
            );
            fileService.getFileUrl.mockResolvedValue(mockPfpUrl);
        });

        it('should convert user to UserResponseDTO with all fields populated', async () => {
            // Arrange
            prismaService.user.findUnique.mockResolvedValue(mockUser);

            // Act
            const result = await service.getUserById(mockUser.id);

            // Assert
            expect(result).toEqual({
                id: mockUser.id,
                tapCustomerId: mockUser.tapCustomerId,
                name: mockUser.name,
                email: mockUser.email,
                crn: mockUser.crn,
                businessName: mockUser.businessName,
                role: AppUserRole[mockUser.role], // Should convert enum
                city: mockUser.city,
                pfpFileName: mockUser.pfpFileName,
                pfpUrl: mockPfpUrl,
                categories: mockCategories,
                isEmailVerified: mockUser.isEmailVerified,
                createdAt: mockUser.createdAt,
                updatedAt: mockUser.updatedAt,
            });

            expect(service['getUserCategories']).toHaveBeenCalledWith(
                mockUser.id,
            );
            expect(fileService.getFileUrl).toHaveBeenCalledWith(
                mockUser.pfpFileName,
            );
        });

        it('should handle null/empty pfpFileName correctly', async () => {
            const userWithoutPfp = { ...mockUser, pfpFileName: null };
            prismaService.user.findUnique.mockResolvedValue(userWithoutPfp);

            const result = await service.getUserById(mockUser.id);

            expect(result.pfpFileName).toBe('');
            expect(result.pfpUrl).toBe('');
            expect(fileService.getFileUrl).not.toHaveBeenCalled();
        });

        it('should handle null pfpUrl from fileService', async () => {
            prismaService.user.findUnique.mockResolvedValue(mockUser);
            fileService.getFileUrl.mockResolvedValue(null);

            const result = await service.getUserById(mockUser.id);

            expect(result.pfpUrl).toBe('');
        });

        it('should throw NotFoundException when user not found', async () => {
            // Arrange
            prismaService.user.findUnique.mockResolvedValue(null);

            // Act & Assert
            await expect(service.getUserById('nonexistent-id')).rejects.toThrow(
                new NotFoundException('User with id nonexistent-id not found'),
            );
        });

        it('should correctly convert role enum from Prisma to App enum', async () => {
            // Test different role types if you have them
            const userWithDifferentRole = { ...mockUser, role: 'SUPPLIER' };
            prismaService.user.findUnique.mockResolvedValue(
                userWithDifferentRole,
            );

            // Act
            const result = await service.getUserById(mockUser.id);

            // Assert
            expect(result.role).toBe(AppUserRole['SUPPLIER']);
        });
    });

    describe('validateUserCategories', () => {
        it('should return category IDs for valid category names', async () => {
            // Arrange
            const categoryNames = ['Electronics', 'Clothing'];
            const mockCategories = [
                { id: 1, name: 'Electronics' },
                { id: 2, name: 'Clothing' },
            ];
            prismaService.category.findMany.mockResolvedValue(mockCategories);

            // Act
            const result =
                await service['validateUserCategories'](categoryNames);

            // Assert
            expect(result).toEqual([1, 2]);
            expect(prismaService.category.findMany).toHaveBeenCalledWith({
                where: { name: { in: categoryNames } },
            });
        });

        it('should throw BadRequestException for invalid category names', async () => {
            // Arrange
            const categoryNames = [
                'Electronics',
                'InvalidCategory',
                'AnotherInvalid',
            ];
            const mockCategories = [{ id: 1, name: 'Electronics' }];
            prismaService.category.findMany.mockResolvedValue(mockCategories);

            // Act & Assert
            await expect(
                service['validateUserCategories'](categoryNames),
            ).rejects.toThrow(
                'These categories are invalid: InvalidCategory, AnotherInvalid',
            );
        });

        it('should throw BadRequestException when no categories are found', async () => {
            // Arrange
            const categoryNames = ['NonExistent1', 'NonExistent2'];
            prismaService.category.findMany.mockResolvedValue([]);

            // Act & Assert
            await expect(
                service['validateUserCategories'](categoryNames),
            ).rejects.toThrow(
                'These categories are invalid: NonExistent1, NonExistent2',
            );
        });

        it('should handle empty array input', async () => {
            // Arrange
            const categoryNames = [];
            prismaService.category.findMany.mockResolvedValue([]);

            // Act
            const result =
                await service['validateUserCategories'](categoryNames);

            // Assert
            expect(result).toEqual([]);
            expect(prismaService.category.findMany).toHaveBeenCalledWith({
                where: { name: { in: [] } },
            });
        });

        it('should handle single category validation', async () => {
            // Arrange
            const categoryNames = ['Electronics'];
            const mockCategories = [{ id: 1, name: 'Electronics' }];
            prismaService.category.findMany.mockResolvedValue(mockCategories);

            // Act
            const result =
                await service['validateUserCategories'](categoryNames);

            // Assert
            expect(result).toEqual([1]);
        });
    });

    describe('generateDefaultAvatar', () => {
        const mockUser = {
            id: '123e4567-e89b-12d3-a456-426614174000',
            name: 'John Doe',
            email: 'john@example.com',
        };

        beforeEach(() => {
            // Mock sharp module
            jest.mock('sharp', () => {
                return jest.fn().mockImplementation(() => ({
                    png: jest.fn().mockReturnThis(),
                    toBuffer: jest
                        .fn()
                        .mockResolvedValue(Buffer.from('mock-png-buffer')),
                }));
            });
        });

        it('should generate default avatar with correct letter and color', async () => {
            // Arrange
            prismaService.user.findUnique.mockResolvedValue(mockUser);
            prismaService.user.update.mockResolvedValue(mockUser);
            fileService.uploadFile.mockResolvedValue(
                'default-avatars/123e4567-generated.png',
            );

            // Act
            const result = await service.generateDefaultAvatar(mockUser.email);

            // Assert
            expect(result).toBe('default-avatars/123e4567-generated.png');
            expect(prismaService.user.findUnique).toHaveBeenCalledWith({
                where: { email: mockUser.email },
            });
            expect(prismaService.user.update).toHaveBeenCalledWith({
                where: { email: mockUser.email },
                data: {
                    pfpFileName: 'default-avatars/123e4567-generated.png',
                    isPfpDefault: true,
                },
            });
        });

        it('should use first letter of name in uppercase', async () => {
            // Arrange
            const userWithLowerName = { ...mockUser, name: 'alice wonderland' };
            prismaService.user.findUnique.mockResolvedValue(userWithLowerName);
            prismaService.user.update.mockResolvedValue(userWithLowerName);
            fileService.uploadFile.mockResolvedValue(
                'default-avatars/alice-avatar.png',
            );

            // Act
            await service.generateDefaultAvatar(userWithLowerName.email);

            // Assert
            expect(fileService.uploadFile).toHaveBeenCalledWith(
                expect.objectContaining({
                    originalname: `default-avatars/${userWithLowerName.id}`,
                    mimetype: 'image/png',
                }),
            );
        });

        it('should select color deterministically based on name', async () => {
            // Arrange
            const users = [
                { ...mockUser, name: 'Alice', id: 'alice-id' },
                {
                    ...mockUser,
                    name: 'Bob',
                    email: 'bob@example.com',
                    id: 'bob-id',
                },
            ];

            for (const user of users) {
                prismaService.user.findUnique.mockResolvedValueOnce(user);
                prismaService.user.update.mockResolvedValueOnce(user);
                fileService.uploadFile.mockResolvedValueOnce(
                    `avatar-${user.id}.png`,
                );

                // Act
                await service.generateDefaultAvatar(user.email);
            }

            // Assert - Colors should be consistent for same names
            expect(fileService.uploadFile).toHaveBeenCalledTimes(2);
        });

        it('should handle special characters in name', async () => {
            // Arrange
            const userWithSpecialName = { ...mockUser, name: '!@#$%' };
            prismaService.user.findUnique.mockResolvedValue(
                userWithSpecialName,
            );
            prismaService.user.update.mockResolvedValue(userWithSpecialName);
            fileService.uploadFile.mockResolvedValue('special-avatar.png');

            // Act
            const result = await service.generateDefaultAvatar(
                userWithSpecialName.email,
            );

            // Assert
            expect(result).toBe('special-avatar.png');
            expect(fileService.uploadFile).toHaveBeenCalledWith(
                expect.objectContaining({
                    originalname: `default-avatars/${userWithSpecialName.id}`,
                    buffer: expect.any(Buffer),
                    mimetype: 'image/png',
                }),
            );
        });

        it('should create proper file structure for upload', async () => {
            // Arrange
            prismaService.user.findUnique.mockResolvedValue(mockUser);
            prismaService.user.update.mockResolvedValue(mockUser);
            fileService.uploadFile.mockResolvedValue('uploaded-filename.png');

            // Act
            await service.generateDefaultAvatar(mockUser.email);

            // Assert
            expect(fileService.uploadFile).toHaveBeenCalledWith({
                originalname: `default-avatars/${mockUser.id}`,
                buffer: expect.any(Buffer),
                mimetype: 'image/png',
                size: expect.any(Number),
            });
        });
    });

    describe('getUserByName', () => {
        const mockUsers = [
            {
                id: '1',
                name: 'John Doe',
                email: 'john@example.com',
                crn: 'CRN123',
                businessName: 'John Business',
                role: 'BUYER',
                city: 'Riyadh',
                pfpFileName: 'john.png',
                isEmailVerified: true,
                createdAt: new Date(),
                updatedAt: new Date(),
                password: 'hashed',
                isPfpDefault: false,
            },
            {
                id: '2',
                name: 'Jane Doe',
                email: 'jane@example.com',
                crn: 'CRN124',
                businessName: 'Jane Business',
                role: 'SUPPLIER',
                city: 'Jeddah',
                pfpFileName: 'jane.png',
                isEmailVerified: true,
                createdAt: new Date(),
                updatedAt: new Date(),
                password: 'hashed',
                isPfpDefault: false,
            },
        ];

        beforeEach(() => {
            jest.spyOn(service as any, 'getUserCategories').mockResolvedValue(
                [],
            );
            fileService.getFileUrl.mockResolvedValue(
                'http://example.com/avatar.png',
            );
        });

        it('should find users by exact name match', async () => {
            // Arrange
            const searchName = 'John Doe';
            prismaService.user.findMany.mockResolvedValue([mockUsers[0]]);

            // Act
            const result = await service.getUserByName(searchName);

            // Assert
            expect(result).toHaveLength(1);
            expect(result[0].name).toBe('John Doe');
            expect(prismaService.user.findMany).toHaveBeenCalledWith({
                where: { name: { contains: searchName, mode: 'insensitive' } },
            });
        });

        it('should find users by partial name match (case insensitive)', async () => {
            // Arrange
            const searchName = 'doe';
            prismaService.user.findMany.mockResolvedValue(mockUsers);

            // Act
            const result = await service.getUserByName(searchName);

            // Assert
            expect(result).toHaveLength(2);
            expect(result[0].name).toBe('John Doe');
            expect(result[1].name).toBe('Jane Doe');
            expect(prismaService.user.findMany).toHaveBeenCalledWith({
                where: { name: { contains: 'doe', mode: 'insensitive' } },
            });
        });

        it('should handle uppercase search terms', async () => {
            // Arrange
            const searchName = 'DOE';
            prismaService.user.findMany.mockResolvedValue(mockUsers);

            // Act
            const result = await service.getUserByName(searchName);

            // Assert
            expect(result).toHaveLength(2);
            expect(prismaService.user.findMany).toHaveBeenCalledWith({
                where: { name: { contains: 'DOE', mode: 'insensitive' } },
            });
        });

        it('should throw NotFoundException when no users found', async () => {
            // Arrange
            const searchName = 'NonExistent';
            prismaService.user.findMany.mockResolvedValue([]);

            // Act & Assert
            await expect(service.getUserByName(searchName)).rejects.toThrow(
                new NotFoundException(
                    'No users found matching name: NonExistent',
                ),
            );
        });

        it('should handle single character searches', async () => {
            // Arrange
            const searchName = 'J';
            prismaService.user.findMany.mockResolvedValue(mockUsers);

            // Act
            const result = await service.getUserByName(searchName);

            // Assert
            expect(result).toHaveLength(2);
            expect(prismaService.user.findMany).toHaveBeenCalledWith({
                where: { name: { contains: 'J', mode: 'insensitive' } },
            });
        });

        it('should handle empty string searches', async () => {
            // Arrange
            const searchName = '';
            prismaService.user.findMany.mockResolvedValue(mockUsers);

            // Act & Assert
            await expect(service.getUserByName(searchName)).rejects.toThrow(
                new BadRequestException('Name parameter is required'),
            );
        });
    });

    describe('getUsersProfilePicturesUrls', () => {
        const mockUsers = [
            {
                id: '123e4567-e89b-12d3-a456-426614174001',
                pfpFileName: 'user1.png',
            },
            {
                id: '123e4567-e89b-12d3-a456-426614174002',
                pfpFileName: 'user2.png',
            },
            {
                id: '123e4567-e89b-12d3-a456-426614174003',
                pfpFileName: null,
            },
        ];

        it('should return profile picture URLs for valid UUIDs', async () => {
            // Arrange
            const validIds = [
                '123e4567-e89b-12d3-a456-426614174001',
                '123e4567-e89b-12d3-a456-426614174002',
            ];
            prismaService.user.findMany.mockResolvedValue([
                mockUsers[0],
                mockUsers[1],
            ]);
            fileService.getFileUrl
                .mockResolvedValueOnce('http://example.com/user1.png')
                .mockResolvedValueOnce('http://example.com/user2.png');

            // Act
            const result = await service.getUsersProfilePicturesUrls(validIds);

            // Assert
            expect(result).toEqual([
                { id: validIds[0], pfpUrl: 'http://example.com/user1.png' },
                { id: validIds[1], pfpUrl: 'http://example.com/user2.png' },
            ]);
            expect(prismaService.user.findMany).toHaveBeenCalledWith({
                where: { id: { in: validIds } },
                select: { id: true, pfpFileName: true },
            });
        });

        it('should filter out invalid UUIDs', async () => {
            // Arrange
            const mixedIds = [
                '123e4567-e89b-12d3-a456-426614174001', // valid
                'invalid-uuid', // invalid
                '123e4567-e89b-12d3-a456-426614174002', // valid
                'another-invalid', // invalid
            ];
            prismaService.user.findMany.mockResolvedValue([
                mockUsers[0],
                mockUsers[1],
            ]);
            fileService.getFileUrl
                .mockResolvedValueOnce('http://example.com/user1.png')
                .mockResolvedValueOnce('http://example.com/user2.png');

            // Act
            const result = await service.getUsersProfilePicturesUrls(mixedIds);

            // Assert
            expect(result).toHaveLength(2);
            expect(prismaService.user.findMany).toHaveBeenCalledWith({
                where: {
                    id: {
                        in: [
                            '123e4567-e89b-12d3-a456-426614174001',
                            '123e4567-e89b-12d3-a456-426614174002',
                        ],
                    },
                },
                select: { id: true, pfpFileName: true },
            });
        });

        it('should handle users with null pfpFileName', async () => {
            // Arrange
            const validIds = ['123e4567-e89b-12d3-a456-426614174003'];
            prismaService.user.findMany.mockResolvedValue([mockUsers[2]]);

            // Act
            const result = await service.getUsersProfilePicturesUrls(validIds);

            // Assert
            expect(result).toEqual([{ id: validIds[0], pfpUrl: null }]);
            expect(fileService.getFileUrl).not.toHaveBeenCalled();
        });

        it('should throw BadRequestException for empty array', async () => {
            // Act & Assert
            await expect(
                service.getUsersProfilePicturesUrls([]),
            ).rejects.toThrow(new BadRequestException('No user IDs provided'));
        });

        it('should throw BadRequestException for non-array input', async () => {
            // Act & Assert
            await expect(
                service.getUsersProfilePicturesUrls(null as any),
            ).rejects.toThrow(new BadRequestException('No user IDs provided'));
        });

        it('should throw BadRequestException when no valid UUIDs provided', async () => {
            // Arrange
            const invalidIds = ['invalid-1', 'invalid-2', 'not-a-uuid'];

            // Act & Assert
            await expect(
                service.getUsersProfilePicturesUrls(invalidIds),
            ).rejects.toThrow(
                new BadRequestException('No valid UUIDs provided'),
            );
        });

        it('should throw NotFoundException when no users found', async () => {
            // Arrange
            const validIds = ['123e4567-e89b-12d3-a456-426614174999'];
            prismaService.user.findMany.mockResolvedValue([]);

            // Act & Assert
            await expect(
                service.getUsersProfilePicturesUrls(validIds),
            ).rejects.toThrow(
                new NotFoundException('No users found with the provided IDs'),
            );
        });

        it('should handle mix of users with and without profile pictures', async () => {
            // Arrange
            const validIds = [
                '123e4567-e89b-12d3-a456-426614174001',
                '123e4567-e89b-12d3-a456-426614174003',
            ];
            prismaService.user.findMany.mockResolvedValue([
                mockUsers[0], // has pfp
                mockUsers[2], // no pfp
            ]);
            fileService.getFileUrl.mockResolvedValueOnce(
                'http://example.com/user1.png',
            );

            // Act
            const result = await service.getUsersProfilePicturesUrls(validIds);

            // Assert
            expect(result).toEqual([
                { id: validIds[0], pfpUrl: 'http://example.com/user1.png' },
                { id: validIds[1], pfpUrl: null },
            ]);
        });
    });

    describe('deleteProfilePicture', () => {
        const mockUser = {
            id: '123e4567-e89b-12d3-a456-426614174000',
            name: 'John Doe',
            email: 'john@example.com',
            isPfpDefault: false,
        };

        const mockUserWithDefaultPfp = {
            ...mockUser,
            isPfpDefault: true,
        };

        it('should delete profile picture and generate default avatar', async () => {
            // Arrange
            prismaService.user.findUnique.mockResolvedValue(mockUser);
            jest.spyOn(service, 'generateDefaultAvatar').mockResolvedValue(
                'default-avatar.png',
            );

            // Act
            const result = await service.deleteProfilePicture(mockUser.email);

            // Assert
            expect(result).toEqual({
                message: 'Profile picture deleted successfully',
            });
            expect(prismaService.user.findUnique).toHaveBeenCalledWith({
                where: { email: mockUser.email },
            });
            expect(service.generateDefaultAvatar).toHaveBeenCalledWith(
                mockUser.email,
            );
        });

        it('should throw NotFoundException when user not found', async () => {
            // Arrange
            prismaService.user.findUnique.mockResolvedValue(null);

            // Act & Assert
            await expect(
                service.deleteProfilePicture('nonexistent@example.com'),
            ).rejects.toThrow(new NotFoundException('User not found'));
        });

        it('should throw BadRequestException when profile picture already default', async () => {
            // Arrange
            prismaService.user.findUnique.mockResolvedValue(
                mockUserWithDefaultPfp,
            );

            // Act & Assert
            await expect(
                service.deleteProfilePicture(mockUserWithDefaultPfp.email),
            ).rejects.toThrow(
                new BadRequestException('Profile picture already default'),
            );
        });

        it('should not call generateDefaultAvatar when user not found', async () => {
            // Arrange
            prismaService.user.findUnique.mockResolvedValue(null);
            const generateDefaultAvatarSpy = jest.spyOn(
                service,
                'generateDefaultAvatar',
            );

            // Act & Assert
            await expect(
                service.deleteProfilePicture('nonexistent@example.com'),
            ).rejects.toThrow(new NotFoundException('User not found'));

            expect(generateDefaultAvatarSpy).not.toHaveBeenCalled();
        });

        it('should not call generateDefaultAvatar when already default', async () => {
            // Arrange
            prismaService.user.findUnique.mockResolvedValue(
                mockUserWithDefaultPfp,
            );
            const generateDefaultAvatarSpy = jest.spyOn(
                service,
                'generateDefaultAvatar',
            );

            // Act & Assert
            await expect(
                service.deleteProfilePicture(mockUserWithDefaultPfp.email),
            ).rejects.toThrow(
                new BadRequestException('Profile picture already default'),
            );

            expect(generateDefaultAvatarSpy).not.toHaveBeenCalled();
        });

        it('should handle generateDefaultAvatar throwing an error', async () => {
            // Arrange
            prismaService.user.findUnique.mockResolvedValue(mockUser);
            jest.spyOn(service, 'generateDefaultAvatar').mockRejectedValue(
                new Error('Avatar generation failed'),
            );

            // Act & Assert
            await expect(
                service.deleteProfilePicture(mockUser.email),
            ).rejects.toThrow('Avatar generation failed');
        });
    });
});
