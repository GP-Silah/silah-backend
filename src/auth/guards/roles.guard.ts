import {
    CanActivate,
    ExecutionContext,
    ForbiddenException,
    Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { Request } from 'express';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class RolesGuard implements CanActivate {
    constructor(
        private reflector: Reflector,
        private readonly jwtService: JwtService,
    ) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const requiredRoles = this.reflector.getAllAndOverride<string[]>(
            ROLES_KEY,
            [context.getHandler(), context.getClass()],
        );

        if (!requiredRoles) return true;

        const request = context.switchToHttp().getRequest<Request>();
        let role = (request as any).tokenData?.role ?? request.tokenData?.role;

        if (!role) {
            // In some cases, the 'token' cookie might be sent as a plain string (e.g., 'abc123'),
            // and in others, it might be sent as an object like { token: 'abc123' }.
            // The next two lines ensures compatibility with both formats by safely extracting the actual token string.
            const tokenObj = request.cookies?.token;
            const token =
                typeof tokenObj === 'string' ? tokenObj : tokenObj?.token;
            const payload = await this.jwtService.verifyAsync(token);
            role = payload.role;
        }

        if (!role || !requiredRoles.includes(role)) {
            throw new ForbiddenException(
                'You do not have access to this resource',
            );
        }

        return true;
    }
}
