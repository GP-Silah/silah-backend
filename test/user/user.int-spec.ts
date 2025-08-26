import { Test, TestingModule } from '@nestjs/testing';
import {
    BadRequestException,
    INestApplication,
    NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { FileService } from 'src/file/file.service';
import { AuthService } from 'src/auth/auth.service';
import { UserService } from 'src/user/user.service';
import { JwtService } from '@nestjs/jwt';
import * as request from 'supertest';
import * as crypto from 'crypto';
import { UserResponseDTO } from 'src/user/dtos/userResponse.dto';
import { UpdateUserDto } from 'src/user/dtos/updateUser.dto';
import { UserRole } from 'src/enums/userRole.enum';
import { AppModule } from 'src/app.module';
import * as cookieParser from 'cookie-parser';

// Mock the sharp library
jest.mock('sharp', () => {
    return jest.fn().mockImplementation(() => ({
        png: jest.fn().mockReturnThis(),
        toBuffer: jest.fn().mockResolvedValue(Buffer.from('mock-png-buffer')),
    }));
});

describe('UserController (Integration)', () => {
    let app: INestApplication;
    let prisma: PrismaService;
    let jwtService: JwtService;
    let authService: Partial<jest.Mocked<AuthService>>;
    let fileService: Partial<jest.Mocked<FileService>>;
    let userService: Partial<jest.Mocked<UserService>>;

    async function generateJwtToken(
        userId: string,
        email: string,
        role: string,
    ) {
        return jwtService.signAsync(
            { sub: userId, email, role, jti: crypto.randomUUID() },
            { secret: process.env.JWT_SECRET || 'test-secret' },
        );
    }

    async function seedTestData() {
        const parentCategories = [
            'Agricultural & Pet Supplies',
            'Beauty & Personal Care',
            'Home & Living',
        ];
        const childCategories = [
            { name: 'Animal Feed', parent: 'Agricultural & Pet Supplies' },
            { name: 'Skincare & Body Care', parent: 'Beauty & Personal Care' },
            { name: 'Furniture', parent: 'Home & Living' },
        ];

        const parentMap = new Map<string, number>();
        for (const name of parentCategories) {
            const category = await prisma.category.upsert({
                where: { name },
                update: {},
                create: { name },
            });
            parentMap.set(name, category.id);
        }

        for (const child of childCategories) {
            const parentId = parentMap.get(child.parent);
            await prisma.category.upsert({
                where: { name: child.name },
                update: {},
                create: { name: child.name, parentCategoryId: parentId },
            });
        }

        const user1 = await prisma.user.create({
            data: {
                id: '123e4567-e89b-12d3-a456-426614174001',
                email: 'test1@example.com',
                crn: '1234500000',
                nid: '6665554443',
                name: 'Test User 1',
                role: 'BUYER',
                businessName: 'Test Business 1',
                city: 'Riyadh',
                password: 'hashed-password',
                isEmailVerified: true,
                pfpFileName: 'test1.png',
                isPfpDefault: false,
                agreedToTerms: true,
            },
        });

        const user2 = await prisma.user.create({
            data: {
                id: '123e4567-e89b-12d3-a456-426614174002',
                email: 'test2@example.com',
                crn: '9994444444',
                nid: '0101053245',
                name: 'Test User 2',
                role: 'SUPPLIER',
                businessName: 'Test Business 2',
                city: 'Jeddah',
                password: 'hashed-password',
                isEmailVerified: false,
                pfpFileName: null,
                isPfpDefault: true,
                agreedToTerms: true,
            },
        });

        await prisma.supplier.create({
            data: {
                id: 'supp-123e4567-e89b-12d3-a456-426614174002',
                userId: user2.id,
                plan: 'BASIC',
                isStoreClosed: true,
                storeClosedMsg: 'Store closed',
                deliveryFees: 0.0,
                avgRating: 0.0,
                ratingCount: 0,
            },
        });

        await prisma.userCategory.createMany({
            data: [
                {
                    userId: user1.id,
                    categoryId: parentMap.get('Agricultural & Pet Supplies')!,
                },
                {
                    userId: user1.id,
                    categoryId: parentMap.get('Beauty & Personal Care')!,
                },
            ],
        });
    }

    beforeAll(async () => {
        fileService = {
            uploadFile: jest.fn().mockResolvedValue('mock-file.png'),
            getFileUrl: jest
                .fn()
                .mockImplementation((fileName: string) =>
                    fileName ? `http://mock-r2.com/${fileName}` : null,
                ),
        };

        authService = {
            sendVerificationEmail: jest.fn().mockResolvedValue(undefined),
            generateEmailVerificationToken: jest
                .fn()
                .mockResolvedValue('mock-verification-token'),
            encryptPassword: jest.fn().mockResolvedValue('hashed-password'),
        };

        const module: TestingModule = await Test.createTestingModule({
            imports: [AppModule],
        })
            .overrideProvider(FileService)
            .useValue(fileService)
            .overrideProvider(AuthService)
            .useValue(authService)
            .compile();

        app = module.createNestApplication();
        app.use(cookieParser());
        prisma = module.get(PrismaService);
        jwtService = module.get(JwtService);
        userService = module.get(UserService); // Get the real UserService

        // Mock only the deleteProfilePicture method
        jest.spyOn(userService, 'deleteProfilePicture').mockImplementation(
            async (email: string) => {
                const user = await prisma.user.findUnique({ where: { email } });
                if (!user) throw new NotFoundException('User not found');
                if (user.isPfpDefault)
                    throw new BadRequestException(
                        'Profile picture already default',
                    );

                const mockFileName = 'default-avatars/default.png';
                await prisma.user.update({
                    where: { email },
                    data: {
                        pfpFileName: mockFileName,
                        isPfpDefault: true,
                    },
                });
                return { message: 'Profile picture deleted successfully' };
            },
        );

        await app.init();
    });

    beforeEach(async () => {
        await prisma.cleanDatabase();
        await seedTestData();
    });

    afterAll(async () => {
        await prisma.$disconnect();
        await app.close();
    });

    describe('GET /users/email/:email', () => {
        it('should return user data for a valid email', async () => {
            const response = await request(app.getHttpServer())
                .get('/users/email/test1@example.com')
                .expect(200);

            expect(response.body).toMatchObject({
                id: '123e4567-e89b-12d3-a456-426614174001',
                email: 'test1@example.com',
                name: 'Test User 1',
                crn: '1234500000',
                businessName: 'Test Business 1',
                city: 'Riyadh',
                role: 'BUYER',
                pfpFileName: 'test1.png',
                pfpUrl: 'http://mock-r2.com/test1.png',
                categories: expect.arrayContaining([
                    'Agricultural & Pet Supplies',
                    'Beauty & Personal Care',
                ]),
                isEmailVerified: true,
            });
        });

        it('should throw NotFoundException for non-existent email', async () => {
            await request(app.getHttpServer())
                .get('/users/email/nonexistent@example.com')
                .expect(404)
                .expect({
                    statusCode: 404,
                    message:
                        'User with email nonexistent@example.com not found',
                    error: 'Not Found',
                });
        });

        it('should throw BadRequestException for invalid email format', async () => {
            await request(app.getHttpServer())
                .get('/users/email/invalid-email')
                .expect(400)
                .expect({
                    statusCode: 400,
                    message: 'Invalid email format',
                    error: 'Bad Request',
                });
        });
    });

    describe('GET /users/crn/:crn', () => {
        it('should return user data for a valid CRN', async () => {
            const response = await request(app.getHttpServer())
                .get('/users/crn/1234500000')
                .expect(200);

            expect(response.body).toMatchObject({
                id: '123e4567-e89b-12d3-a456-426614174001',
                crn: '1234500000',
                email: 'test1@example.com',
            });
        });

        it('should throw NotFoundException for non-existent CRN', async () => {
            await request(app.getHttpServer())
                .get('/users/crn/9965434321')
                .expect(404)
                .expect({
                    statusCode: 404,
                    message: 'User with CRN 9965434321 not found',
                    error: 'Not Found',
                });
        });
    });

    describe('GET /users/name/:name', () => {
        it('should return users matching name', async () => {
            const response = await request(app.getHttpServer())
                .get('/users/name?name=Test')
                .expect(200);

            expect(response.body).toHaveLength(2);
            expect(response.body[0]).toMatchObject({
                name: 'Test User 1',
                email: 'test1@example.com',
            });
            expect(response.body[1]).toMatchObject({
                name: 'Test User 2',
                email: 'test2@example.com',
            });
        });

        it('should throw NotFoundException for non-matching name', async () => {
            await request(app.getHttpServer())
                .get('/users/name?name=NonExistent')
                .expect(404)
                .expect({
                    statusCode: 404,
                    message: 'No users found matching name: NonExistent',
                    error: 'Not Found',
                });
        });

        it('should throw BadRequestException for empty name search', async () => {
            await request(app.getHttpServer())
                .get('/users/name?name=')
                .expect(400)
                .expect({
                    statusCode: 400,
                    message: 'Name parameter is required',
                    error: 'Bad Request',
                });
        });
    });

    describe('GET /users/me', () => {
        it('should return current user data with valid token', async () => {
            const token = await generateJwtToken(
                '123e4567-e89b-12d3-a456-426614174001',
                'test1@example.com',
                'BUYER',
            );

            const response = await request(app.getHttpServer())
                .get('/users/me')
                .set('Cookie', `token=${token}`)
                .expect(200);

            expect(response.body).toMatchObject({
                id: '123e4567-e89b-12d3-a456-426614174001',
                email: 'test1@example.com',
                role: 'BUYER',
            });
        });

        it('should throw UnauthorizedException for missing token', async () => {
            await request(app.getHttpServer())
                .get('/users/me')
                .expect(401)
                .expect({
                    statusCode: 401,
                    message: 'No token found in cookies',
                    error: 'Unauthorized',
                });
        });

        it('should throw UnauthorizedException for invalid token', async () => {
            await request(app.getHttpServer())
                .get('/users/me')
                .set('Cookie', `token=invalid-token`)
                .expect(401)
                .expect({
                    statusCode: 401,
                    message: 'Invalid or expired token',
                    error: 'Unauthorized',
                });
        });

        it('should throw NotFoundException for non-existent user', async () => {
            const token = await generateJwtToken(
                'nonexistent-id',
                'nonexistent@example.com',
                'BUYER',
            );

            await request(app.getHttpServer())
                .get('/users/me')
                .set('Cookie', `token=${token}`)
                .expect(404)
                .expect({
                    statusCode: 404,
                    message: 'User data not found',
                    error: 'Not Found',
                });
        });
    });

    describe('PATCH /users/me', () => {
        it('should update user data with valid token and input', async () => {
            const token = await generateJwtToken(
                '123e4567-e89b-12d3-a456-426614174001',
                'test1@example.com',
                'BUYER',
            );

            const updateDto: UpdateUserDto = {
                name: 'Updated User',
                email: 'updated@example.com',
                businessName: 'Updated Business',
                city: 'Jeddah',
                newPassword: 'newPassword123',
                categories: ['Home & Living'],
            };

            const response = await request(app.getHttpServer())
                .patch('/users/me')
                .set('Cookie', `token=${token}`)
                .send(updateDto)
                .expect(200);

            expect(response.body).toMatchObject({
                name: 'Updated User',
                email: 'updated@example.com',
                businessName: 'Updated Business',
                city: 'Jeddah',
                categories: ['Home & Living'],
            });

            const updatedUser = await prisma.user.findUnique({
                where: { id: '123e4567-e89b-12d3-a456-426614174001' },
            });
            expect(updatedUser?.name).toBe('Updated User');
            expect(updatedUser?.email).toBe('updated@example.com');
        });

        it('should throw BadRequestException for invalid categories', async () => {
            const token = await generateJwtToken(
                '123e4567-e89b-12d3-a456-426614174001',
                'test1@example.com',
                'BUYER',
            );

            const updateDto = { categories: ['Invalid Category'] };

            await request(app.getHttpServer())
                .patch('/users/me')
                .set('Cookie', `token=${token}`)
                .send(updateDto)
                .expect(400)
                .expect({
                    statusCode: 400,
                    message: 'These categories are invalid: Invalid Category',
                    error: 'Bad Request',
                });
        });

        it('should handle partial updates', async () => {
            const token = await generateJwtToken(
                '123e4567-e89b-12d3-a456-426614174001',
                'test1@example.com',
                'BUYER',
            );

            const updateDto = { name: 'Partial Update' };

            const response = await request(app.getHttpServer())
                .patch('/users/me')
                .set('Cookie', `token=${token}`)
                .send(updateDto)
                .expect(200);

            expect(response.body.name).toBe('Partial Update');
            expect(response.body.email).toBe('test1@example.com');
        });
    });

    describe('POST /users/me/profile-picture', () => {
        it('should update profile picture with valid token', async () => {
            const token = await generateJwtToken(
                '123e4567-e89b-12d3-a456-426614174001',
                'test1@example.com',
                'BUYER',
            );

            const file = {
                fieldname: 'file',
                originalname: 'profile.jpg',
                encoding: '7bit',
                mimetype: 'image/jpeg',
                buffer: Buffer.from('mock-file-content'),
                size: 1024,
            };

            const response = await request(app.getHttpServer())
                .post('/users/me/profile-picture')
                .set('Cookie', `token=${token}`)
                .attach('file', file.buffer, 'profile.jpg')
                .expect(201);

            expect(response.body).toEqual({
                message: 'Profile picture updated successfully',
                pfpFileName: 'mock-file.png',
            });

            expect(fileService.uploadFile).toHaveBeenCalledWith(
                expect.objectContaining({
                    originalname: 'profile.jpg',
                    mimetype: 'image/jpeg',
                }),
            );

            const user = await prisma.user.findUnique({
                where: { id: '123e4567-e89b-12d3-a456-426614174001' },
            });
            expect(user?.pfpFileName).toBe('mock-file.png');
            expect(user?.isPfpDefault).toBe(false);
        });

        it('should throw UnauthorizedException for missing token', async () => {
            await request(app.getHttpServer())
                .post('/users/me/profile-picture')
                .expect(401)
                .expect({
                    statusCode: 401,
                    message: 'No token found in cookies',
                    error: 'Unauthorized',
                });
        });
    });

    describe('DELETE /users/me/profile-picture', () => {
        it('should delete profile picture and set default', async () => {
            const token = await generateJwtToken(
                '123e4567-e89b-12d3-a456-426614174001',
                'test1@example.com',
                'BUYER',
            );

            const response = await request(app.getHttpServer())
                .delete('/users/me/profile-picture')
                .set('Cookie', `token=${token}`)
                .expect(200);

            expect(response.body).toEqual({
                message: 'Profile picture deleted successfully',
            });

            const user = await prisma.user.findUnique({
                where: { id: '123e4567-e89b-12d3-a456-426614174001' },
            });
            expect(user?.isPfpDefault).toBe(true);
            expect(user?.pfpFileName).toBe('default-avatars/default.png');
        });

        it('should throw BadRequestException if already default', async () => {
            const token = await generateJwtToken(
                '123e4567-e89b-12d3-a456-426614174002',
                'test2@example.com',
                'SUPPLIER',
            );

            await request(app.getHttpServer())
                .delete('/users/me/profile-picture')
                .set('Cookie', `token=${token}`)
                .expect(400)
                .expect({
                    statusCode: 400,
                    message: 'Profile picture already default',
                    error: 'Bad Request',
                });
        });
    });

    describe('GET /users/:id/profile-picture', () => {
        it('should return profile picture URL for valid user ID', async () => {
            const response = await request(app.getHttpServer())
                .get(
                    '/users/123e4567-e89b-12d3-a456-426614174001/profile-picture',
                )
                .expect(200);

            expect(response.body).toEqual({
                pfpUrl: 'http://mock-r2.com/test1.png',
            });
        });

        it('should throw NotFoundException for non-existent user', async () => {
            await request(app.getHttpServer())
                .get('/users/nonexistent-id/profile-picture')
                .expect(404)
                .expect({
                    statusCode: 404,
                    message: 'Profile picture not found',
                    error: 'Not Found',
                });
        });

        it('should throw NotFoundException for user with no profile picture', async () => {
            await request(app.getHttpServer())
                .get(
                    '/users/123e4567-e89b-12d3-a456-426614174002/profile-picture',
                )
                .expect(404)
                .expect({
                    statusCode: 404,
                    message: 'Profile picture not found',
                    error: 'Not Found',
                });
        });
    });

    describe('POST /users/profile-pictures/batch', () => {
        it('should return profile picture URLs for valid user IDs', async () => {
            const response = await request(app.getHttpServer())
                .post('/users/profile-pictures/batch')
                .set('Content-Type', 'application/json')
                .send({
                    ids: [
                        '123e4567-e89b-12d3-a456-426614174001',
                        '123e4567-e89b-12d3-a456-426614174002',
                    ],
                })
                .expect(201);

            expect(response.body).toEqual([
                {
                    id: '123e4567-e89b-12d3-a456-426614174001',
                    pfpUrl: 'http://mock-r2.com/test1.png',
                },
                { id: '123e4567-e89b-12d3-a456-426614174002', pfpUrl: null },
            ]);
        });

        it('should throw BadRequestException for empty ID array', async () => {
            await request(app.getHttpServer())
                .post('/users/profile-pictures/batch')
                .set('Content-Type', 'application/json')
                .send({ ids: [] })
                .expect(400)
                .expect({
                    statusCode: 400,
                    message: 'No user IDs provided',
                    error: 'Bad Request',
                });
        });

        it('should throw BadRequestException for invalid UUIDs', async () => {
            await request(app.getHttpServer())
                .post('/users/profile-pictures/batch')
                .set('Content-Type', 'application/json')
                .send({ ids: ['invalid-uuid'] })
                .expect(400)
                .expect({
                    statusCode: 400,
                    message: 'No valid UUIDs provided',
                    error: 'Bad Request',
                });
        });

        it('should throw NotFoundException for non-existent users', async () => {
            await request(app.getHttpServer())
                .post('/users/profile-pictures/batch')
                .set('Content-Type', 'application/json')
                .send({ ids: ['123e4567-e89b-12d3-a456-426614174999'] })
                .expect(404)
                .expect({
                    statusCode: 404,
                    message: 'No users found with the provided IDs',
                    error: 'Not Found',
                });
        });
    });
});
