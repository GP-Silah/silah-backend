import {
  Body,
  Controller,
  Get,
  Param,
  Patch,
  Req,
  UseGuards,
} from '@nestjs/common';
import { UserService } from './user.service';
import {
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiOperation,
  ApiParam,
  ApiTags,
} from '@nestjs/swagger';
import { Request } from 'express';
import { UpdateUserDto } from './dtos/updateUser.dto';
import { ParseEmailPipe } from 'src/pipes/parse-email.pipe';
import { ParseCrnPipe } from 'src/pipes/parse-crn.pipe';
import { UserResponseDTO } from './dtos/userResponse.dto';
import { ApiJwtAuthGuard } from 'src/auth/decorators/api-jwt-auth-guard.decorator';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth/jwt-auth.guard';

@ApiTags('Users')
@Controller('users')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Get('email/:email')
  @ApiOperation({
    summary: 'Get user by email',
    description: 'Fetches a single user using their email address.',
  })
  @ApiParam({
    name: 'email',
    type: String,
    description: 'Email address of the user',
    example: 'example@email.com',
  })
  @ApiOkResponse({
    description: 'User found',
    type: UserResponseDTO,
  })
  @ApiNotFoundResponse({
    description: 'User not found',
    schema: {
      example: {
        statusCode: 404,
        message: 'User not found',
        error: 'Not Found',
      },
    },
  })
  async getUserByEmail(
    @Param('email', new ParseEmailPipe()) email: string,
  ): Promise<UserResponseDTO> {
    return this.userService.getUserByEmail(email);
  }

  @Get('crn/:crn')
  @ApiOperation({
    summary: 'Get user by their CRN',
    description: 'Fetches a user using their unique CRN.',
  })
  @ApiParam({
    name: 'crn',
    type: String,
    description: 'Customer Registration Number of the user',
    example: '0123456789',
  })
  @ApiOkResponse({
    description: 'User found',
    type: UserResponseDTO,
  })
  @ApiNotFoundResponse({
    description: 'User not found',
    schema: {
      example: {
        statusCode: 404,
        message: 'User not found',
        error: 'Not Found',
      },
    },
  })
  async getUserByCRN(
    @Param('crn', new ParseCrnPipe()) crn: string,
  ): Promise<UserResponseDTO> {
    return this.userService.getUserByCRN(crn);
  }

  @Get('name/:name')
  @ApiOperation({
    summary: 'Search users by name',
    description: 'Returns a list of users that match the provided name.',
  })
  @ApiParam({
    name: 'name',
    type: String,
    description: 'Name to search users by',
    example: 'Sarah',
  })
  @ApiOkResponse({
    description: 'Users found',
    type: [UserResponseDTO],
  })
  @ApiNotFoundResponse({
    description: 'No users found',
    schema: {
      example: {
        statusCode: 404,
        message: 'No users found with the name',
        error: 'Not Found',
      },
    },
  })
  async getUserByName(@Param('name') name: string): Promise<UserResponseDTO[]> {
    return this.userService.getUserByName(name);
  }

  @ApiJwtAuthGuard()
  @UseGuards(JwtAuthGuard)
  @Get('me')
  @ApiOperation({
    summary: 'Get current user',
    description: "Returns the currently authenticated user's data.",
  })
  @ApiOkResponse({
    description: 'Current user data retrieved successfully',
    type: UserResponseDTO,
  })
  async getCurrentUserData(@Req() req: Request): Promise<UserResponseDTO> {
    const userId = req.tokenData!.sub;
    return this.userService.getCurrentUserData(userId);
  }

  @ApiJwtAuthGuard()
  @UseGuards(JwtAuthGuard)
  //TODO api docs for this endpoint
  @Patch('me')
  async updateCurrnetUserData(
    @Body() dto: UpdateUserDto,
    @Req() req: Request,
  ): Promise<UserResponseDTO> {
    return this.userService.updateCurrentUserData(dto, req.tokenData!.sub);
  }
}
