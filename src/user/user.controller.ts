import { Body, Controller, Get, Param, Patch, Req } from '@nestjs/common';
import { UserService } from './user.service';
import { ApiTags } from '@nestjs/swagger';
import { Request } from 'express';
import { UpdateUserDto } from './dtos/updateUser.dto';
import { ParseEmailPipe } from 'src/pipes/parse-email.pipe';
import { ParseCrnPipe } from 'src/pipes/parse-crn.pipe';

@ApiTags('Users')
@Controller('users')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Get('email/:email')
  async getUserByEmail(@Param('email', new ParseEmailPipe()) email: string) {}

  @Get('crn/:crn')
  async getUserByCRN(@Param('crn', new ParseCrnPipe()) crn: string) {}

  @Get('name/:name')
  async getUserByName(@Param('name') name: string) {}

  @Get('me')
  async getCurrentUserData(@Req() req: Request) {}

  @Patch('me')
  async updateCurrnetUserData(
    @Body() dto: UpdateUserDto,
    @Req() req: Request,
  ) {}
}
