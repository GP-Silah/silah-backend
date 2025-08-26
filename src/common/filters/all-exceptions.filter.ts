import {
    ExceptionFilter,
    Catch,
    ArgumentsHost,
    HttpException,
} from '@nestjs/common';
import logger from '../../logger';

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
    catch(exception: unknown, host: ArgumentsHost) {
        const ctx = host.switchToHttp();
        const response = ctx.getResponse();
        const request = ctx.getRequest();

        const status =
            exception instanceof HttpException ? exception.getStatus() : 500;

        const message =
            exception instanceof HttpException
                ? exception.getResponse()
                : exception;

        // Log the error
        logger.error(
            `${request.method} ${request.url} ${JSON.stringify(message)}`,
        );

        response.status(status).json({
            statusCode: status,
            timestamp: new Date().toISOString(),
            path: request.url,
            error: message,
        });
    }
}
