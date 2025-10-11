import { NestFactory } from '@nestjs/core';
import { AppModule } from '../src/app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import * as fs from 'fs';
import { SupplierResponseDto } from 'src/supplier/dtos/supplierResponse.dto';
import { InactiveSupplierResponseDto } from 'src/supplier/dtos/inactiveSupplierResponse.dto';
import { CheckoutRedirectDto } from 'src/cart/dtos/checkoutRedirect.dto';
import { ProductResponseDto } from 'src/product/dtos/productResponse.dto';
import { ServiceResponseDto } from 'src/service/dtos/serviceResponse.dto';

async function generateSwagger() {
    const app = await NestFactory.create(AppModule, { logger: false });

    // Swagger configuration
    const config = new DocumentBuilder()
        .setTitle('Silah Backend API Documentation')
        .setDescription(
            `
Use this documentation to explore, test, and understand the available API endpoints, their request/response structure, and any required parameters such as headers, cookies, or authentication tokens.

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
            'bearer', // scheme name
        )
        .build();

    // Create Swagger document with extraModels
    const document = SwaggerModule.createDocument(app, config, {
        extraModels: [
            SupplierResponseDto,
            InactiveSupplierResponseDto,
            CheckoutRedirectDto,
            ProductResponseDto,
            ServiceResponseDto,
        ],
    });

    // Define tags
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
        { name: 'Demand Predictions' },
    ];

    // Setup Swagger UI (optional if you want to launch locally)
    SwaggerModule.setup('api/docs', app, document, {
        swaggerOptions: {
            tagsSorter: 'none', // keep tag order
            operationsSorter: 'alpha', // optional: sort operations inside tags
        },
    });

    // Write swagger.json
    fs.mkdirSync('./docs', { recursive: true });
    fs.writeFileSync('./docs/swagger.json', JSON.stringify(document, null, 2));

    console.log('Swagger JSON generated successfully!');
    await app.close();
}

generateSwagger();
