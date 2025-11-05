import {
    Body,
    Controller,
    Delete,
    FileTypeValidator,
    Get,
    MaxFileSizeValidator,
    Param,
    ParseFilePipe,
    Patch,
    Post,
    Query,
    Req,
    UseGuards,
    UseInterceptors,
    Headers,
    UploadedFiles,
    BadRequestException,
    UploadedFile,
} from '@nestjs/common';
import { ProductService } from './product.service';
import { ApiTags } from '@nestjs/swagger';
import { ApiDocsJwtAuthGuard } from 'src/auth/decorators/jwt-auth-guard.docs';
import { ApiDocsRolesGuard } from 'src/auth/decorators/roles-guard.docs';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { UserRole } from 'src/enums/userRole.enum';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { FileInterceptor, FilesInterceptor } from '@nestjs/platform-express';
import { Request } from 'express';
import { CreateProductDto } from './dtos/createProduct.dto';
import {
    ApiDocsCreateProduct,
    ApiDocsDeleteProduct,
    ApiDocsDeleteProductImage,
    ApiDocsDuplicateProduct,
    ApiDocsFakeGetCreateProductDto,
    ApiDocsGetAllProducts,
    ApiDocsGetAllSupplierProducts,
    ApiDocsGetProductById,
    ApiDocsUpdateProduct,
    ApiDocsUpdateProductImage,
} from './product.docs';
import { UpdateProductDto } from './dtos/updateProduct.dto';
import { validateOrReject, ValidationError } from 'class-validator';
import { ApiDocsVerifiedGuard } from 'src/auth/decorators/verified-guard.docs';
import { VerifiedGuard } from 'src/auth/guards/verified.guard';

@ApiTags('Products')
@Controller('products')
export class ProductController {
    constructor(private readonly productService: ProductService) {}

    @Get()
    @ApiDocsGetAllProducts()
    async getAllProducts(
        @Req() req: Request,
        @Headers('accept-language') langHeader?: 'ar' | 'en',
        @Query('lang') lang?: 'ar' | 'en',
    ) {
        const userId = req.tokenData?.sub;
        const finalLang = lang || langHeader || 'en';
        return this.productService.getAllProducts(finalLang, userId);
    }

    @Get(':productId')
    @ApiDocsGetProductById()
    async getProductById(
        @Param('productId') productId: string,
        @Req() req: Request,
        @Headers('accept-language') langHeader?: 'ar' | 'en',
        @Query('lang') lang?: 'ar' | 'en',
    ) {
        const userId = req.tokenData?.sub;
        const finalLang = lang || langHeader || 'en';
        return this.productService.getProductById(productId, finalLang, userId);
    }

    @Get('supplier/:supplierId')
    @ApiDocsGetAllSupplierProducts()
    async getAllSupplierProducts(
        @Param('supplierId') supplierId: string,
        @Req() req: Request,
        @Headers('accept-language') langHeader?: 'ar' | 'en',
        @Query('lang') lang?: 'ar' | 'en',
    ) {
        const userId = req.tokenData?.sub;
        const finalLang = lang || langHeader || 'en';
        return this.productService.getAllSupplierProducts(
            supplierId,
            finalLang,
            userId,
        );
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @Post()
    @UseInterceptors(FilesInterceptor('files', 3)) // note: "files" for multiple files
    @ApiDocsCreateProduct()
    async createProduct(
        @UploadedFiles(
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
        files: Express.Multer.File[],
        @Req() req: Request,
        // @Body('dto', ParseJsonPipe) dto: CreateProductDto,
    ) {
        // Parse the dto from req.body manually (because NestJS way throws errors and workarounds failed)
        let dto: CreateProductDto;
        try {
            dto = JSON.parse(req.body.dto);
        } catch (err) {
            throw new BadRequestException('Invalid JSON in form field');
        }
        // Run validation
        try {
            await validateOrReject(Object.assign(new CreateProductDto(), dto));
        } catch (errors) {
            // errors is ValidationError[]
            const messages = (errors as ValidationError[])
                .map((err) => {
                    if (err.constraints) {
                        return Object.values(err.constraints).join('; ');
                    }
                    return '';
                })
                .filter((msg) => !!msg)
                .join('; ');

            throw new BadRequestException(messages || 'Validation failed');
        }
        const userId = req.tokenData!.sub;
        return this.productService.createProduct(userId, dto, files);
    }
    @Get('create-product-dto')
    @ApiDocsFakeGetCreateProductDto()
    dummy() {
        return; // Never called
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @Post(':productId/clone')
    @ApiDocsDuplicateProduct()
    async duplicateProduct(
        @Param('productId') productId: string,
        @Req() req: Request,
    ) {
        const userId = req.tokenData!.sub;
        return this.productService.duplicateProduct(userId, productId);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @Patch(':productId')
    @ApiDocsUpdateProduct()
    async updateProduct(
        @Param('productId') productId: string,
        @Req() req: Request,
        @Body() dto: UpdateProductDto,
    ) {
        const userId = req.tokenData!.sub;
        return this.productService.updateProduct(userId, productId, dto);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @UseInterceptors(FileInterceptor('file'))
    @Patch(':productId/images')
    @ApiDocsUpdateProductImage()
    async updateProductImages(
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
        @Param('productId') productId: string,
        @Req() req: Request,
    ) {
        const userId = req.tokenData!.sub;
        return this.productService.updateProductImages(userId, productId, file);
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @Delete(':productId/image/:fileName')
    @ApiDocsDeleteProductImage()
    async deleteProductImage(
        @Param('productId') productId: string,
        @Param('fileName') fileName: string,
        @Req() req: Request,
    ) {
        const userId = req.tokenData!.sub;
        return this.productService.deleteProductImage(
            userId,
            productId,
            fileName,
        );
    }

    @ApiDocsJwtAuthGuard()
    @ApiDocsRolesGuard()
    @ApiDocsVerifiedGuard()
    @Roles(UserRole.SUPPLIER)
    @UseGuards(JwtAuthGuard, RolesGuard, VerifiedGuard)
    @Delete(':productId')
    @ApiDocsDeleteProduct()
    async deleteProduct(
        @Param('productId') productId: string,
        @Req() req: Request,
    ) {
        const userId = req.tokenData!.sub;
        return this.productService.deleteProduct(userId, productId);
    }
}
