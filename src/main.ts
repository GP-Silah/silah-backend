import * as dotenv from 'dotenv';
dotenv.config({ path: '.env.merged' });

import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import * as cookieParser from 'cookie-parser';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import * as fs from 'fs';
import { AllExceptionsFilter } from './common/filters/all-exceptions.filter';
import { ThrottlerGuard } from '@nestjs/throttler';

async function bootstrap() {
    const app = await NestFactory.create(AppModule);

    app.setGlobalPrefix('api');

    app.useGlobalGuards(app.get(ThrottlerGuard));

    app.useGlobalPipes(
        new ValidationPipe({
            whitelist: true,
            forbidNonWhitelisted: true,
            transform: true,
        }),
    );

    app.useGlobalFilters(new AllExceptionsFilter());

    app.enableCors({
        origin: `${process.env.FRONTEND_URL}`,
        credentials: true,
    });

    app.use(cookieParser());

    // Swagger config
    const config = new DocumentBuilder()
        .setTitle('Silah Backend API Documentation')
        .setDescription(
            'Use this documentation to explore, test, and understand the available API endpoints, their request/response structure, and any required parameters such as headers, cookies, or authentication tokens.',
        )
        .setVersion('1.0')
        .addCookieAuth('token')
        .addSecurity('cookie', {
            type: 'apiKey',
            in: 'cookie',
            name: 'token', // name of the cookie that stores the token/session
        })
        .build();
    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('api/docs', app, document); // => will be lunched on http://localhost:3000/api/docs
    fs.mkdirSync('./docs', { recursive: true });
    fs.writeFileSync('./docs/swagger.json', JSON.stringify(document, null, 2)); // => to create a swagger.json file that will be used to generate static files of swagger to deploy on "silah-api-docs", which is a static website "https://docs.silah.site".

    await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
