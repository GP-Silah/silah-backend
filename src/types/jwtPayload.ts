import { UserRole } from 'src/enums/userRole.enum';

export interface JwtPayload {
    sub: string;
    email: string;
    role: UserRole;
    isVerified: boolean;
}
