import { ApiProperty } from '@nestjs/swagger';

export class ForecastMonthDto {
    @ApiProperty({
        example: '2025-01',
        description: 'The forecasted month in YYYY-MM format',
    })
    month: string;

    @ApiProperty({
        example: 120,
        description: 'Total predicted demand for this month',
    })
    demand: number;
}

export class DemandPredictionResponseDto {
    @ApiProperty({
        example: '123',
        description: 'ID of the product being forecasted',
    })
    product_id: string;

    @ApiProperty({
        type: [ForecastMonthDto],
        description:
            'List of monthly demand predictions for the requested horizon',
    })
    forecast: ForecastMonthDto[];

    @ApiProperty({
        example: false,
        description:
            'Indicates if the prediction accuracy is low (true when sales history < 50 days)',
    })
    lowAccuracy: boolean;

    @ApiProperty({
        example: 42,
        description: 'Total number of days of past sales data used in training',
    })
    salesCount: number;

    @ApiProperty({
        example: 210,
        description:
            'How many additional units supplier should stock to meet forecasted demand',
    })
    recommendedStock: number;
}
