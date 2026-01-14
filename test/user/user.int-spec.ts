// test/user/user.int-spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import {
  INestApplication,
  ValidationPipe,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../../src/app.module';
import { PrismaService } from '../../src/prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { FileService } from '../../src/file/file.service';
import { AuthService } from '../../src/auth/auth.service';
import { UserService } from '../../src/user/user.service';
import * as cookieParser from 'cookie-parser';

jest.mock('sharp', () => {
  return jest.fn().mockImplementation(() => ({
    resize: jest.fn().mockReturnThis(),
    png: jest.fn().mockReturnThis(),
    toBuffer: jest.fn().mockResolvedValue(Buffer.from('mock-png')),
  }));
});

describe('UserController (Integration - Real AppModule)', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  let jwtService: JwtService;
  let fileService: jest.Mocked<FileService>;
  let authService: jest.Mocked<AuthService>;

  const BUYER_ID = '123e4567-e89b-12d3-a456-426614174001';
  const SUPPLIER_ID = '123e4567-e89b-12d3-a456-426614174002';

  async function createToken(userId: string, email: string, role: 'BUYER' | 'SUPPLIER') {
    return jwtService.signAsync(
      { sub: userId, email, role },
      { secret: 'test-secret' }
    );
  }

  async function seedDatabase() {
    await prisma.category.upsert({
      where: { name: 'Agricultural & Pet Supplies' },
      update: {},
      create: { name: 'Agricultural & Pet Supplies', usedFor: 'PRODUCT' },
    });
    await prisma.category.upsert({
      where: { name: 'Beauty & Personal Care' },
      update: {},
      create: { name: 'Beauty & Personal Care', usedFor: 'PRODUCT' },
    });
    await prisma.category.upsert({
      where: { name: 'Home & Living' },
      update: {},
      create: { name: 'Home & Living', usedFor: 'PRODUCT' },
    });

    await prisma.user.upsert({
      where: { id: BUYER_ID },
      update: {},
      create: {
        id: BUYER_ID,
        email: 'buyer@test.com',
        name: 'Ahmad Buyer',
        crn: '1111111111',
        nid: '1234567890',
        businessName: 'Ahmad Trading Co',
        role: 'BUYER',
        city: 'Riyadh',
        password: 'hashed',
        isEmailVerified: true,
        pfpFileName: 'buyer.png',
        isPfpDefault: false,
        tapCustomerId: 'tap_000000000000000000000000', // string, not null
        preferredLanguage: 'EN',
        agreedToTerms: true,
      },
    });

    await prisma.user.upsert({
      where: { id: SUPPLIER_ID },
      update: {},
      create: {
        id: SUPPLIER_ID,
        email: 'supplier@test.com',
        name: 'Mohammed Supplier',
        crn: '2222222222',
        nid: '0987654321',
        businessName: 'Mohammed Supplies LLC',
        role: 'SUPPLIER',
        city: 'Jeddah',
        password: 'hashed',
        isEmailVerified: true,
        pfpFileName: null,
        isPfpDefault: true,
        tapCustomerId: 'tap_999999999999999999999999', // string
        preferredLanguage: 'EN',
        agreedToTerms: true,
      },
    });

    const categories = await prisma.category.findMany();
    await prisma.userCategory.createMany({
      data: [
        { userId: BUYER_ID, categoryId: categories[0].id },
        { userId: BUYER_ID, categoryId: categories[1].id },
      ],
      skipDuplicates: true,
    });
  }

  beforeAll(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(FileService)
      .useValue({
        uploadFile: jest.fn().mockResolvedValue('uploaded-mock.png'),
        getFileUrl: jest.fn().mockImplementation((name: string) =>
          name ? `https://r2.mock.dev/${name}` : null
        ),
      })
      .overrideProvider(AuthService)
      .useValue({
        sendVerificationEmail: jest.fn(),
        generateEmailVerificationToken: jest.fn().mockResolvedValue('token-xyz'),
        encryptPassword: jest.fn().mockResolvedValue('new-hashed'),
      })
      .compile();

    app = module.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));
    app.use(cookieParser());
    await app.init();

    prisma = module.get(PrismaService);
    jwtService = module.get(JwtService);
    fileService = module.get(FileService);
    authService = module.get(AuthService);

    const userService = module.get(UserService);
    jest.spyOn(userService, 'deleteProfilePicture').mockImplementation(async (email: string) => {
      const user = await prisma.user.findUnique({ where: { email } });
      if (!user) throw new NotFoundException('User not found');
      if (user.isPfpDefault) throw new BadRequestException('Profile picture already default');

      await prisma.user.update({
        where: { email },
        data: { pfpFileName: 'default.png', isPfpDefault: true },
      });
      return { message: 'Profile picture deleted successfully' };
    });
  });

  beforeEach(async () => {
    await prisma.cleanDatabase();
    await seedDatabase();
  });

  afterAll(async () => {
    await prisma.$disconnect();
    await app.close();
  });

  // ====================== ROBUST ASSERTIONS ======================

  describe('GET /users/email/:email', () => {
    it('should return full user profile with correct structure', async () => {
      const res = await request(app.getHttpServer())
        .get('/users/email/buyer@test.com')
        .expect(200);

      expect(res.body).toMatchObject({
        id: BUYER_ID,
        email: 'buyer@test.com',
        name: 'Ahmad Buyer',
        crn: '1111111111',
        businessName: 'Ahmad Trading Co',
        city: 'Riyadh',
        role: 'BUYER',
        isEmailVerified: true,
        pfpFileName: 'buyer.png',
        pfpUrl: 'https://r2.mock.dev/buyer.png',
        categories: expect.arrayContaining([
          'Agricultural & Pet Supplies',
          'Beauty & Personal Care',
        ]),
      });
      expect(Array.isArray(res.body.categories)).toBe(true);
      expect(res.body.categories.length).toBeGreaterThan(0);
    });

    it('should return 404 for unknown email', () => {
      return request(app.getHttpServer())
        .get('/users/email/unknown@silah.com')
        .expect(404)
        .expect(res => {
          expect(res.body.message).toContain('not found');
        });
    });
  });

  describe('GET /users/me', () => {
    it('should return authenticated user with all fields', async () => {
      const token = await createToken(BUYER_ID, 'buyer@test.com', 'BUYER');

      const res = await request(app.getHttpServer())
        .get('/users/me')
        .set('Cookie', `token=${token}`)
        .expect(200);

      expect(res.body).toMatchObject({
        id: BUYER_ID,
        email: 'buyer@test.com',
        role: 'BUYER',
        name: 'Ahmad Buyer',
        city: 'Riyadh',
      });
      expect(Array.isArray(res.body.categories)).toBe(true);
      expect(res.body.categories.length).toBe(2);
    });

    it('should reject missing token', () => {
      return request(app.getHttpServer()).get('/users/me').expect(401);
    });
  });

  describe('PATCH /users/me', () => {
    it('should update name and city correctly', async () => {
      const token = await createToken(BUYER_ID, 'buyer@test.com', 'BUYER');

      const res = await request(app.getHttpServer())
        .patch('/users/me')
        .set('Cookie', `token=${token}`)
        .send({ name: 'Updated Name', city: 'Dammam' })
        .expect(200);

      expect(res.body.name).toBe('Updated Name');
      expect(res.body.city).toBe('Dammam');

      // DB check
      const user = await prisma.user.findUnique({ where: { id: BUYER_ID } });
      expect(user?.name).toBe('Updated Name');
      expect(user?.city).toBe('Dammam');
    });
  });

  describe('POST /users/me/profile-picture', () => {
    it('should upload and update profile picture', async () => {
      const token = await createToken(BUYER_ID, 'buyer@test.com', 'BUYER');

      const res = await request(app.getHttpServer())
        .post('/users/me/profile-picture')
        .set('Cookie', `token=${token}`)
        .attach('file', Buffer.from('fake-png-data'), 'photo.png')
        .expect(201);

      expect(res.body).toEqual({
        message: 'Profile picture updated successfully',
        pfpFileName: 'uploaded-mock.png',
      });

      const user = await prisma.user.findUnique({ where: { id: BUYER_ID } });
      expect(user?.pfpFileName).toBe('uploaded-mock.png');
      expect(user?.isPfpDefault).toBe(false);
    });
  });

  describe('DELETE /users/me/profile-picture', () => {
    it('should remove picture and set default', async () => {
      const token = await createToken(BUYER_ID, 'buyer@test.com', 'BUYER');

      await request(app.getHttpServer())
        .delete('/users/me/profile-picture')
        .set('Cookie', `token=${token}`)
        .expect(200);

      const user = await prisma.user.findUnique({ where: { id: BUYER_ID } });
      expect(user?.isPfpDefault).toBe(true);
      expect(user?.pfpFileName).toBe('default.png');
    });

    it('should 400 when already default', async () => {
      const token = await createToken(SUPPLIER_ID, 'supplier@test.com', 'SUPPLIER');

      await request(app.getHttpServer())
        .delete('/users/me/profile-picture')
        .set('Cookie', `token=${token}`)
        .expect(400);
    });
  });

  describe('GET /users/:id/profile-picture', () => {
    it('should return correct URL', () => {
      return request(app.getHttpServer())
        .get(`/users/${BUYER_ID}/profile-picture`)
        .expect(200)
        .expect({ pfpUrl: 'https://r2.mock.dev/buyer.png' });
    });

    it('should 404 when no picture', () => {
      return request(app.getHttpServer())
        .get(`/users/${SUPPLIER_ID}/profile-picture`)
        .expect(404);
    });
  });

  describe('POST /users/profile-pictures/batch', () => {
    it('should return correct URLs for multiple users', async () => {
      const res = await request(app.getHttpServer())
        .post('/users/profile-pictures/batch')
        .send({ ids: [BUYER_ID, SUPPLIER_ID] })
        .expect(201);

      expect(res.body).toHaveLength(2);
      expect(res.body).toContainEqual({
        id: BUYER_ID,
        pfpUrl: 'https://r2.mock.dev/buyer.png',
      });
      expect(res.body).toContainEqual({
        id: SUPPLIER_ID,
        pfpUrl: null,
      });
    });
  });
});
