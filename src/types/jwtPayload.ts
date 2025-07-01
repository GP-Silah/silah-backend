import { UserRole } from 'src/enums/userRole';

export interface JwtPayload {
  sub: string;
  email: string;
  role: UserRole;
}
