// src/common/guards/verified.guard.ts
import {
    CanActivate,
    ExecutionContext,
    ForbiddenException,
    Injectable,
} from '@nestjs/common';
import { Request } from 'express';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class VerifiedGuard implements CanActivate {
    constructor(private readonly jwtService: JwtService) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest<Request>();
        let isVerified =
            (request as any).tokenData?.isVerified ??
            request.tokenData?.isVerified;

        if (isVerified == null) {
            // In some cases, the 'token' cookie might be sent as a plain string (e.g., 'abc123'),
            // and in others, it might be sent as an object like { token: 'abc123' }.
            // The next two lines ensures compatibility with both formats by safely extracting the actual token string.
            const tokenObj = request.cookies?.token;
            const token =
                typeof tokenObj === 'string' ? tokenObj : tokenObj?.token;
            const payload = await this.jwtService.verifyAsync(token);
            isVerified = payload.isVerified;
        }

        if (!isVerified) {
            throw new ForbiddenException('User email is not verified');
        }

        return true;
    }
}
