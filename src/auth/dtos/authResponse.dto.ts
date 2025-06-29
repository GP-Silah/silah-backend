import { UserResponseDTO } from 'src/user/dtos/userResponse.dto';

export class AuthResponseDto {
  token: string;
  user: UserResponseDTO;
}
