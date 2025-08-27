import {
    ExceptionFilter,
    Catch,
    ArgumentsHost,
    HttpException,
    HttpStatus,
} from '@nestjs/common';
import { Request, Response } from 'express';
import logger from '../../logger';

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
    catch(exception: unknown, host: ArgumentsHost) {
        const ctx = host.switchToHttp();
        const response = ctx.getResponse<Response>();
        const request = ctx.getRequest<Request>();

        const isHttp = exception instanceof HttpException;
        const status = isHttp
            ? exception.getStatus()
            : HttpStatus.INTERNAL_SERVER_ERROR;

        // Normalize client-facing payload
        const responseError = isHttp
            ? (() => {
                  const res = exception.getResponse();
                  // If response is string, wrap it in { message }
                  return typeof res === 'string' ? { message: res } : res;
              })()
            : { message: 'Internal server error' };

        // Log full details internally
        if (!isHttp && exception instanceof Error) {
            logger.error(
                `${request.method} ${request.url} ${status} - ${exception.message}\n${exception.stack}`,
            );
        } else {
            logger.error(
                `${request.method} ${request.url} ${status} - ${JSON.stringify(responseError)}`,
            );
        }

        // Send normalized error to client
        response.status(status).json({
            statusCode: status,
            timestamp: new Date().toISOString(),
            path: request.url,
            error: responseError,
        });
    }
}
