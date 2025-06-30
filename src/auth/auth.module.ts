import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { IsEmailOrCrnConstraint } from './dtos/isEmailOrCrnConstraint';

/**
 * AuthModule is responsible for handling authentication-related features
 * such as user signup and JWT configuration.
 */
@Module({
  imports: [
    JwtModule.register({
      global: true,
      secret: process.env.JWT_SECRET,
      signOptions: { expiresIn: '1d' },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, IsEmailOrCrnConstraint],
})
export class AuthModule {}
