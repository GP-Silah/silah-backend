import { UserRole } from '../../enums/userRole';

export class UpdateUserDto {
  uuid: string;
  name?: string;
  email?: string;
  businessName?: string;
  city?: string;
  pfpUrl?: string;
  role?: UserRole;
  isVerified?: boolean;
}
