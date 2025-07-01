import { UserRole } from '../../enums/userRole';

export class UserResponseDTO {
  uuid: string;
  name: string;
  email: string;
  crn: string;
  isVerified: boolean;
  role: UserRole;
  businessName: string;
  city: string;
  nid: string;
  pfpUrl?: string;
  createdAt: Date;
  updatedAt: Date;
}
