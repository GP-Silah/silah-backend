import { applyDecorators } from '@nestjs/common';
import {
    ApiBearerAuth,
    ApiOperation,
    ApiOkResponse,
    ApiNotFoundResponse,
    ApiUnauthorizedResponse,
    ApiBadRequestResponse,
    ApiBadGatewayResponse,
    ApiParam,
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
                'Returns monthly demand predictions, forecast accuracy indicators, and a stocking recommendation. ' +
                'If the product has fewer than the minimum required sales days, a Bad Request error is returned.',
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
        ApiBadRequestResponse({
            description: 'Not enough sales data to generate a forecast',
            schema: {
                example: {
                    statusCode: 400,
                    message:
                        'Not enough sales data to forecast. Minimum 10 sales days required, found 3.',
                    error: 'Bad Request',
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
