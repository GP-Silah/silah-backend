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
} from '@nestjs/common';
import { UserService } from './user.service';
import { ApiTags } from '@nestjs/swagger';
import { Request } from 'express';
import { UpdateUserDto } from './dtos/updateUser.dto';
import { ParseEmailPipe } from 'src/pipes/parse-email.pipe';
import { ParseCrnPipe } from 'src/pipes/parse-crn.pipe';
import { UserResponseDTO } from './dtos/userResponse.dto';
import { ApiJwtAuthGuard } from 'src/auth/decorators/api-jwt-auth-guard.decorator';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth/jwt-auth.guard';
import {
    GetUserByCrnApiDocs,
    GetUserByEmailApiDocs,
    GetUserByNameApiDocs,
    GetCurrentUserDataApiDocs,
    UpdateCurrentUserDataApiDocs,
    GetUserProfilePictureApiDocs,
    GetUsersProfilePicturesUrlsApiDocs,
    DeleteProfilePictureApiDocs,
    UploadProfilePictureApiDocs,
} from './user.docs';
import { FileInterceptor } from '@nestjs/platform-express';

@ApiTags('Users')
@Controller('users')
export class UserController {
    constructor(private readonly userService: UserService) {}

    @Get('email/:email')
    @GetUserByEmailApiDocs()
    async getUserByEmail(
        @Param('email', new ParseEmailPipe()) email: string,
    ): Promise<UserResponseDTO> {
        return this.userService.getUserByEmail(email);
    }

    @Get('crn/:crn')
    @GetUserByCrnApiDocs()
    async getUserByCRN(
        @Param('crn', new ParseCrnPipe()) crn: string,
    ): Promise<UserResponseDTO> {
        return this.userService.getUserByCRN(crn);
    }

    @Get('name/:name')
    @GetUserByNameApiDocs()
    async getUserByName(
        @Param('name') name: string,
    ): Promise<UserResponseDTO[]> {
        return this.userService.getUserByName(name);
    }

    @ApiJwtAuthGuard()
    @UseGuards(JwtAuthGuard)
    @Get('me')
    @GetCurrentUserDataApiDocs()
    async getCurrentUserData(@Req() req: Request): Promise<UserResponseDTO> {
        const userId = req.tokenData!.sub;
        return this.userService.getCurrentUserData(userId);
    }

    @ApiJwtAuthGuard()
    @UseGuards(JwtAuthGuard)
    @Patch('me')
    @UpdateCurrentUserDataApiDocs()
    async updateCurrentUserData(
        @Body() dto: UpdateUserDto,
        @Req() req: Request,
    ): Promise<UserResponseDTO> {
        return this.userService.updateCurrentUserData(dto, req.tokenData!.sub);
    }

    @ApiJwtAuthGuard()
    @UseGuards(JwtAuthGuard)
    @Post('me/profile-picture')
    @UploadProfilePictureApiDocs()
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
    @DeleteProfilePictureApiDocs()
    async deleteProfilePicture(@Req() req: Request) {
        return this.userService.deleteProfilePicture(req.tokenData!.email);
    }

    @Get(':id/profile-picture')
    @GetUserProfilePictureApiDocs()
    async getUserProfilePictureUrl(@Param('id') userId: string) {
        return this.userService.getUserProfilePictureUrl(userId);
    }

    @Post('profile-pictures/batch')
    @GetUsersProfilePicturesUrlsApiDocs()
    async getUsersProfilePicturesUrls(@Body() body: { ids: string[] }) {
        return this.userService.getUsersProfilePicturesUrls(body.ids);
    }
}
