import { forwardRef, Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { IsEmailOrCrnConstraint } from './dtos/isEmailOrCrnConstraint';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { UserModule } from '../user/user.module';
import { TapPaymentsModule } from 'src/tap-payments/tap-payments.module';
import { WathqModule } from 'src/wathq/wathq.module';

/**
 * AuthModule is responsible for handling authentication-related features
 * such as user signup and JWT configuration.
 */
@Module({
    imports: [
        ConfigModule,
        JwtModule.registerAsync({
            imports: [ConfigModule],
            inject: [ConfigService],
            useFactory: (configService: ConfigService) => ({
                secret: configService.get<string>('JWT_SECRET'),
                signOptions: { expiresIn: '1d' },
            }),
            global: true,
        }),
        forwardRef(() => UserModule),
        TapPaymentsModule,
        WathqModule,
    ],
    controllers: [AuthController],
    providers: [AuthService, IsEmailOrCrnConstraint],
    exports: [AuthService],
})
export class AuthModule {}
