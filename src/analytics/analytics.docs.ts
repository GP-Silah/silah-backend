import { applyDecorators } from '@nestjs/common';
import {
    ApiOperation,
    ApiOkResponse,
    ApiNotFoundResponse,
} from '@nestjs/swagger';
import { AnalyticsResponseDTO } from './dtos/analyticsResponse.dto';

export function ApiDocsGetMyAnalytics() {
    return applyDecorators(
        ApiOperation({
            summary: 'Get supplier analytics data',
            description: `Retrieves a comprehensive analytics report for the authenticated supplier account.<br><br>
Includes:
<ul>
  <li><b>Revenue by Month:</b> Orders & invoices totals for the past 3 months (including this month).</li>
  <li><b>Top Items:</b> Most ordered and wishlisted products/services.</li>
  <li><b>Reviews:</b> Average rating and recent reviews in the same period.</li>
</ul>`,
        }),
        ApiOkResponse({
            description:
                'Successfully retrieved analytics summary for supplier.',
            type: AnalyticsResponseDTO,
        }),
        ApiNotFoundResponse({
            description: 'Supplier not found or deleted.',
            schema: {
                example: {
                    statusCode: 404,
                    message: 'Supplier not found or deleted.',
                    error: 'Not Found',
                },
            },
        }),
    );
}
