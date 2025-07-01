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
    const tokenObj = request.cookies?.token;

    if (!tokenObj || typeof tokenObj.token !== 'string') {
      throw new UnauthorizedException('No token found in cookies');
    }

    try {
      const payload = await this.jwtService.verifyAsync(tokenObj.token);
      request.tokenData = payload;
      return true;
    } catch (err) {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }
}
