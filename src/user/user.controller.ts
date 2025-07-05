import { Controller, Get, Param, Patch } from '@nestjs/common';
import { UserService } from './user.service';
import { ApiTags } from '@nestjs/swagger';

@ApiTags('Users')
@Controller('users')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Get('')
  async getUserData() {}

  @Get(':id')
  async getUserById(@Param('id') id: string) {}

  @Patch('')
  async updateUser() {}
}

// Find user by: Id, Email, CRN, Name