import { NestFactory } from '@nestjs/core';
import { AppModule } from '../src/app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import * as fs from 'fs';

async function generateSwagger() {
    const app = await NestFactory.create(AppModule, { logger: false });

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
            name: 'token',
        })
        .build();

    const document = SwaggerModule.createDocument(app, config);
    fs.mkdirSync('./docs', { recursive: true });
    fs.writeFileSync('./docs/swagger.json', JSON.stringify(document, null, 2));
    console.log('Swagger JSON generated successfully!');
    await app.close();
}

generateSwagger();
