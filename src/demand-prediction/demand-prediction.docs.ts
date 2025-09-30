import { applyDecorators } from '@nestjs/common';
import {
    ApiBearerAuth,
    ApiOperation,
    ApiOkResponse,
    ApiNotFoundResponse,
    ApiUnauthorizedResponse,
    ApiParam,
    ApiBadGatewayResponse,
} from '@nestjs/swagger';
import { DemandPredictionResponseDto } from './dtos/demandPredictionResponse.dto';

export function ApiDocsGetDemandPrediction() {
    return applyDecorators(
        ApiBearerAuth(),
        ApiOperation({
            summary: 'Get demand prediction for a product',
            description:
                'Generates a 3-month sales forecast for a specific product using Prophet (via the AI backend). ' +
                'Requires the supplier to be authenticated and subscribed to a plan higher than BASIC. ' +
                'Returns monthly demand predictions, forecast accuracy indicators, and a stocking recommendation.',
        }),
        ApiParam({
            name: 'productId',
            type: String,
            description: 'ID of the product to generate demand prediction for',
            example: 'uuid-product-id',
        }),
        ApiOkResponse({
            description: 'Demand prediction generated successfully',
            type: DemandPredictionResponseDto,
        }),
        ApiNotFoundResponse({
            description: 'Supplier or product not found',
            schema: {
                oneOf: [
                    {
                        example: {
                            statusCode: 404,
                            message: 'Supplier not found',
                            error: 'Not Found',
                        },
                    },
                    {
                        example: {
                            statusCode: 404,
                            message: 'Product not found',
                            error: 'Not Found',
                        },
                    },
                ],
            },
        }),
        ApiUnauthorizedResponse({
            description: 'Supplier plan does not allow access to predictions',
            schema: {
                example: {
                    statusCode: 401,
                    message: 'Upgrade plan to access this feature',
                    error: 'Unauthorized',
                },
            },
        }),
        ApiBadGatewayResponse({
            description: 'AI backend failed to return prediction',
            schema: {
                example: {
                    statusCode: 502,
                    message: 'Failed to get prediction from AI backend',
                    error: 'Bad Gateway',
                },
            },
        }),
    );
}
