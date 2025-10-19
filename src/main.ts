import * as dotenv from 'dotenv';
dotenv.config({ path: '.env.merged' });

import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import * as cookieParser from 'cookie-parser';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import * as fs from 'fs';
import { AllExceptionsFilter } from './common/filters/all-exceptions.filter';
import { SupplierResponseDto } from './supplier/dtos/supplierResponse.dto';
import { InactiveSupplierResponseDto } from './supplier/dtos/inactiveSupplierResponse.dto';
import { CheckoutRedirectDto } from './cart/dtos/checkoutRedirect.dto';
import { ProductResponseDto } from './product/dtos/productResponse.dto';
import { ServiceResponseDto } from './service/dtos/serviceResponse.dto';
import {
    InvoiceResponseDto,
    PreInvoiceResponseDto,
} from './invoice/dtos/invoiceResponse.dto';

async function bootstrap() {
    const app = await NestFactory.create(AppModule);

    app.enableShutdownHooks();

    app.setGlobalPrefix('api');

    app.useGlobalPipes(
        new ValidationPipe({
            whitelist: true,
            forbidNonWhitelisted: true,
            transform: true,
        }),
    );

    app.useGlobalFilters(new AllExceptionsFilter());

    app.enableCors({
        origin:
            process.env.NODE_ENV === 'production'
                ? process.env.FRONTEND_URL?.split(',')
                      .map((o) => o.trim())
                      .filter(Boolean)
                : ['http://localhost:5173'], // explicit React dev origin so SSE work
        credentials: true,
    });

    app.use(cookieParser());

    // Swagger config
    const config = new DocumentBuilder()
        .setTitle('Silah Backend API Documentation')
        .setDescription(
            `
Use this documentation to explore, test, and understand the available API endpoints, their request/response structure, and any required parameters such as headers, cookies, or authentication tokens.

\`\`\`text
[ base URL: https://api.silah.site ]
\`\`\`

**Important Note about Error Responses**

When you test the APIs here in Swagger UI, the error responses are shown in a *simplified* format (only what we document in each endpoint).  

In real life, the server wraps these responses inside a bigger error object because of our logging system.  

For example, Swagger might show this error response for an endpoint that requires authentication and receives no token:

\`\`\`json
{
  "statusCode": 401,
  "message": "No token found in cookies",
  "error": "Unauthorized"
}
\`\`\`

But the actual response you will receive when calling the API from your frontend will look like this:

\`\`\`json
{
  "statusCode": 401,
  "timestamp": "2025-09-07T07:24:11.173Z",
  "path": "/api/auth/switch-role",
  "error": {
    "statusCode": 401,
    "message": "No token found in cookies",
    "error": "Unauthorized"
  }
}
\`\`\`

How to use this on frontend:
- Always read the \`error.message\` property if you want to show an error to the user.  
- Ignore \`timestamp\` and \`path\` (they're for debugging).  
- The shape in Swagger helps you know *what kinds of messages to expect*, but real responses are wrapped as shown above.
`,
        )
        .setVersion('1.0')
        .addCookieAuth('token') // cookie scheme
        .addBearerAuth(
            { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
            'bearer', // name of the scheme
        )
        .build();

    const document = SwaggerModule.createDocument(app, config, {
        extraModels: [
            SupplierResponseDto,
            InactiveSupplierResponseDto,
            CheckoutRedirectDto,
            ProductResponseDto,
            ServiceResponseDto,
            InvoiceResponseDto,
            PreInvoiceResponseDto,
        ], // extraModels is crucial when using $ref in oneOf, anyOf, or allOf.
    });
    document.tags = [
        { name: 'Default' },
        { name: 'Health' },
        { name: 'Auth' },
        { name: 'Users' },
        { name: 'Buyers' },
        { name: 'Suppliers' },
        { name: 'Categories' },
        { name: 'Products' },
        { name: 'Services' },
        { name: 'Search' },
        { name: 'Smart Search' },
        { name: 'Carts' },
        { name: 'Orders' },
        { name: 'Invoices' },
        { name: 'Reviews' },
        { name: 'Group Purchases' },
        { name: 'Bids' },
        { name: 'Offers' },
        { name: 'Demand Predictions' },
        { name: 'Analytics' },
        { name: 'Notifications' },
        { name: 'Chats' },
    ];
    SwaggerModule.setup('api/docs', app, document, {
        swaggerOptions: {
            tagsSorter: 'none', // don’t alphabetize
            operationsSorter: 'alpha', // optional: keep endpoints sorted inside a tag
        },
    }); // => will be lunched on http://localhost:3000/api/docs
    fs.mkdirSync('./docs', { recursive: true });
    fs.writeFileSync('./docs/swagger.json', JSON.stringify(document, null, 2)); // => to create a swagger.json file that will be used to generate static files of swagger to deploy on "silah-api-docs", which is a static website "https://docs.silah.site".

    await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
