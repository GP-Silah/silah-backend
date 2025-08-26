import {
    Body,
    Controller,
    Delete,
    Get,
    Param,
    Patch,
    Post,
    Req,
    UseGuards,
    UseInterceptors,
    UploadedFile,
    UsePipes,
    BadRequestException,
    Logger,
    Query,
} from '@nestjs/common';
import { UserService } from './user.service';
import { ApiTags } from '@nestjs/swagger';
import { Request } from 'express';
import { UpdateUserDto } from './dtos/updateUser.dto';
import { ParseEmailPipe } from '../pipes/parse-email.pipe';
import { ParseCrnPipe } from '../pipes/parse-crn.pipe';
import { UserResponseDTO } from './dtos/userResponse.dto';
import { ApiJwtAuthGuard } from '../auth/decorators/api-jwt-auth-guard.decorator';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import {
    ApiDocsGetUserByCrn,
    ApiDocsGetUserByEmail,
    ApiDocsGetUserByName,
    ApiDocsGetCurrentUserData,
    ApiDocsUpdateCurrentUserData,
    ApiDocsGetUserProfilePicture,
    ApiDocsGetUsersProfilePicturesUrls,
    ApiDocsDeleteProfilePicture,
    ApiDocsUploadProfilePicture,
} from './user.docs';
import { FileInterceptor } from '@nestjs/platform-express';

@ApiTags('Users')
@Controller('users')
export class UserController {
    constructor(private readonly userService: UserService) {}

    @Get('email/:email')
    @ApiDocsGetUserByEmail()
    async getUserByEmail(
        @Param('email', new ParseEmailPipe()) email: string,
    ): Promise<UserResponseDTO> {
        return this.userService.getUserByEmail(email);
    }

    @Get('crn/:crn')
    @ApiDocsGetUserByCrn()
    async getUserByCRN(
        @Param('crn', new ParseCrnPipe()) crn: string,
    ): Promise<UserResponseDTO> {
        return this.userService.getUserByCRN(crn);
    }

    @Get('name')
    @ApiDocsGetUserByName()
    async getUserByName(
        @Query('name') name: string,
    ): Promise<UserResponseDTO[]> {
        if (!name || name.trim() === '') {
            throw new BadRequestException('Name parameter is required');
        }
        return this.userService.getUserByName(name);
    }

    @ApiJwtAuthGuard()
    @UseGuards(JwtAuthGuard)
    @Get('me')
    @ApiDocsGetCurrentUserData()
    async getCurrentUserData(@Req() req: Request): Promise<UserResponseDTO> {
        const userId = req.tokenData!.sub;
        return this.userService.getCurrentUserData(userId);
    }

    @ApiJwtAuthGuard()
    @UseGuards(JwtAuthGuard)
    @Patch('me')
    @ApiDocsUpdateCurrentUserData()
    async updateCurrentUserData(
        @Body() dto: UpdateUserDto,
        @Req() req: Request,
    ): Promise<UserResponseDTO> {
        return this.userService.updateCurrentUserData(dto, req.tokenData!.sub);
    }

    @ApiJwtAuthGuard()
    @UseGuards(JwtAuthGuard)
    @Post('me/profile-picture')
    @ApiDocsUploadProfilePicture()
    @UseInterceptors(FileInterceptor('file')) // "file" = form field name
    async updateProfilePicture(
        @UploadedFile() file: Express.Multer.File,
        @Req() req: Request,
    ) {
        return this.userService.updateProfilePicture(
            file,
            req.tokenData!.email,
        );
    }

    @ApiJwtAuthGuard()
    @UseGuards(JwtAuthGuard)
    @Delete('me/profile-picture')
    @ApiDocsDeleteProfilePicture()
    async deleteProfilePicture(@Req() req: Request) {
        return this.userService.deleteProfilePicture(req.tokenData!.email);
    }

    @Get(':id/profile-picture')
    @ApiDocsGetUserProfilePicture()
    async getUserProfilePictureUrl(@Param('id') userId: string) {
        return this.userService.getUserProfilePictureUrl(userId);
    }

    @Post('profile-pictures/batch')
    @UsePipes() // Disable global ValidationPipe for this endpoint
    @ApiDocsGetUsersProfilePicturesUrls()
    async getUsersProfilePicturesUrls(@Body() body: { ids?: string[] }) {
        const logger = new Logger('UserController');
        logger.log(`Received request body: ${JSON.stringify(body)}`);

        if (!body || !Array.isArray(body.ids)) {
            throw new BadRequestException(
                'Request body must contain an "ids" array',
            );
        }
        return await this.userService.getUsersProfilePicturesUrls(body.ids);
    }
}
