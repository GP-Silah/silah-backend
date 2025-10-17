import { Module } from '@nestjs/common';
import { CategoryService } from './category.service';
import { CategoryController } from './category.controller';
import { TranslationModule } from 'src/translation/translation.module';

@Module({
    imports: [TranslationModule],
    controllers: [CategoryController],
    providers: [CategoryService],
})
export class CategoryModule {}
