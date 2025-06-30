import { BadRequestException, Injectable } from '@nestjs/common';
import { SignupDto } from './dtos/signup.dto';
import * as bcrypt from 'bcrypt';
import { PrismaService } from 'src/prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  async encryptPassword(
    plainText: string,
    saltRounds: number = 10,
  ): Promise<string> {
    return await bcrypt.hash(plainText, saltRounds);
  }

  async comparePasswords(
    hashedPassword: string,
    plainText: string,
  ): Promise<boolean> {
    return await bcrypt.compare(plainText, hashedPassword);
  }

  async signUp(payload: SignupDto): Promise<{ token: string }> {
    // Validate that the recieved categories exists in DB, and convert them to IDs to store them later
    const categories = await this.prisma.category.findMany({
      where: { name: { in: payload.categories } },
    });
    if (categories.length !== payload.categories.length) {
      const foundNames = categories.map((c) => c.name);
      const missing = payload.categories.filter(
        (name) => !foundNames.includes(name),
      );
      throw new BadRequestException(
        `These categories are invalid: ${missing.join(', ')}`,
      );
    }
    const categoryIds = categories.map((c) => c.id);

    // Insure that the NID, CRN, Email are unique in DB
    const existingUser = await this.prisma.user.findFirst({
      where: {
        OR: [
          { nid: payload.nid },
          { crn: payload.crn },
          { email: payload.email },
        ],
      },
    });
    if (existingUser) {
      if (existingUser.nid === payload.nid) {
        throw new BadRequestException('NID already exists');
      }
      if (existingUser.crn === payload.crn) {
        throw new BadRequestException('CRN already exists');
      }
      if (existingUser.email === payload.email) {
        throw new BadRequestException('Email already exists');
      }
    }

    // Hash the password and store the user in DB
    const hashedPassword = await this.encryptPassword(payload.password);
    const user = await this.prisma.user.create({
      data: {
        ...payload,
        password: hashedPassword,
        categories: {
          create: categoryIds.map((categoryId) => ({
            category: {
              connect: { id: categoryId },
            },
          })),
        },
      },
    });

    // Generate a JWT token and return it to the controller so it sends it as a cookie
    const token = await this.jwtService.signAsync({
      sub: user.id, // Standard JWT subject claim
      email: user.email, // Useful for some identity checks
      role: user.role, // For role-based access
    });
    return { token };
  }
}
