import {
    CanActivate,
    ExecutionContext,
    Injectable,
    UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';

@Injectable()
export class JwtAuthGuard implements CanActivate {
    constructor(private readonly jwtService: JwtService) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest<Request>();
        // In some cases, the 'token' cookie might be sent as a plain string (e.g., 'abc123'),
        // and in others, it might be sent as an object like { token: 'abc123' }.
        // The next two lines ensures compatibility with both formats by safely extracting the actual token string.
        const tokenObj = request.cookies?.token;
        const token = typeof tokenObj === 'string' ? tokenObj : tokenObj?.token;

        if (!token || typeof token !== 'string') {
            throw new UnauthorizedException('No token found in cookies');
        }

        try {
            const payload = await this.jwtService.verifyAsync(token);
            request.tokenData = payload;
            return true;
        } catch (err) {
            throw new UnauthorizedException('Invalid or expired token');
        }
    }
}
