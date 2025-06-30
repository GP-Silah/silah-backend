import { Controller, Get, Param, Patch, Post } from '@nestjs/common';
import { UserService } from './user.service';

@Controller('users')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Get('')
  async getUserData() {}

  @Get(':id')
  async getUserById(@Param('id') id: string) {}

  @Patch('')
  async updateUser() {}

  @Patch('switch-role')
  async switchUserRole() {}

  //? Does the Auth call this? if so why has this as a route?? Look into this
  @Post('create-user')
  async createUser() {}
}

// Find user by: Id, Email, CRN, Name
//? CheckDuplicates shouldn't this be on the auth?
//TODO: Look into the UserModule as a whole after implementing the Auth
//TODO: Docs
