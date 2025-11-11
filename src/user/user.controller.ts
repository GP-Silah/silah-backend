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
    BadRequestException,
    Logger,
    ParseFilePipe,
    MaxFileSizeValidator,
    FileTypeValidator,
} from '@nestjs/common';
import { UserService } from './user.service';
import { ApiTags } from '@nestjs/swagger';
import { Request } from 'express';
import { UpdateUserDto } from './dtos/updateUser.dto';
import { ParseEmailPipe } from '../pipes/parse-email.pipe';
import { ParseCrnPipe } from '../pipes/parse-crn.pipe';
import { UserResponseDTO } from './dtos/userResponse.dto';
import { ApiDocsJwtAuthGuard } from '../auth/decorators/jwt-auth-guard.docs';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import {
    ApiDocsGetUserByCrn,
    ApiDocsGetUserByEmail,
    ApiDocsGetCurrentUserData,
    ApiDocsUpdateCurrentUserData,
    ApiDocsGetUserProfilePicture,
    ApiDocsGetUsersProfilePicturesUrls,
    ApiDocsDeleteProfilePicture,
    ApiDocsUploadProfilePicture,
    ApiDocsSwitchPreferredLanguage,
    ApiDocsGetUserById,
} from './user.docs';
import { FileInterceptor } from '@nestjs/platform-express';

@ApiTags('Users')
@Controller('users')
export class UserController {
    constructor(private readonly userService: UserService) {}

    @Get('id/:id')
    @ApiDocsGetUserById()
    async getUserById(@Param('id') userId: string) {
        return this.userService.exposedGetUserById(userId);
    }

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

    @ApiDocsJwtAuthGuard()
    @UseGuards(JwtAuthGuard)
    @Get('me')
    @ApiDocsGetCurrentUserData()
    async getCurrentUserData(@Req() req: Request): Promise<UserResponseDTO> {
        const userId = req.tokenData!.sub;
        return this.userService.getCurrentUserData(userId);
    }

    @ApiDocsJwtAuthGuard()
    @UseGuards(JwtAuthGuard)
    @Patch('me')
    @ApiDocsUpdateCurrentUserData()
    async updateCurrentUserData(
        @Body() dto: UpdateUserDto,
        @Req() req: Request,
    ): Promise<UserResponseDTO> {
        return this.userService.updateCurrentUserData(dto, req.tokenData!.sub);
    }

    @ApiDocsJwtAuthGuard()
    @UseGuards(JwtAuthGuard)
    @Post('me/profile-picture')
    @ApiDocsUploadProfilePicture()
    @UseInterceptors(FileInterceptor('file')) // "file" = form field name
    async updateProfilePicture(
        @UploadedFile(
            new ParseFilePipe({
                validators: [
                    new MaxFileSizeValidator({ maxSize: 5 * 1024 * 1024 }),
                    new FileTypeValidator({
                        fileType: /^image\/(png|jpe?g|webp)$/i,
                        skipMagicNumbersValidation: true,
                    }),
                ],
            }),
        )
        file: Express.Multer.File,
        @Req() req: Request,
    ) {
        return this.userService.updateProfilePicture(
            file,
            req.tokenData!.email,
        );
    }

    @ApiDocsJwtAuthGuard()
    @UseGuards(JwtAuthGuard)
    @Delete('me/profile-picture')
    @ApiDocsDeleteProfilePicture()
    async deleteProfilePicture(@Req() req: Request) {
        return this.userService.deleteProfilePicture(req.tokenData!.email);
    }

    @ApiDocsJwtAuthGuard()
    @UseGuards(JwtAuthGuard)
    @Patch('me/preferred-language')
    @ApiDocsSwitchPreferredLanguage()
    async switchPreferredLanguage(@Req() req: Request) {
        return this.userService.switchPreferredLanguage(req.tokenData!.email);
    }

    @Get(':id/profile-picture')
    @ApiDocsGetUserProfilePicture()
    async getUserProfilePictureUrl(@Param('id') userId: string) {
        return this.userService.getUserProfilePictureUrl(userId);
    }

    @Post('profile-pictures/batch')
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
