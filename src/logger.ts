import { createLogger, format, transports } from 'winston';
import * as DailyRotateFile from 'winston-daily-rotate-file';

// Format for logs
const logFormat = format.printf(({ timestamp, level, message }) => {
    return `${timestamp} [${level.toUpperCase()}]: ${message}`;
});

// Logger configuration
const logger = createLogger({
    level: 'debug', // log everything (debug, warn, error)
    format: format.combine(
        format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        logFormat,
    ),
    transports: [
        // Console output for Docker logs
        new transports.Console(),

        // Error logs file
        new DailyRotateFile({
            filename: 'logs/error-%DATE%.log',
            level: 'error',
            datePattern: 'YYYY-MM-DD',
            maxFiles: '10d',
            zippedArchive: true,
        }),

        // Debug logs file
        new DailyRotateFile({
            filename: 'logs/debug-%DATE%.log',
            level: 'debug',
            datePattern: 'YYYY-MM-DD',
            maxFiles: '10d',
            zippedArchive: true,
        }),
    ],
});

export default logger;
