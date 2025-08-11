import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import path from 'path';

// eslint-disable-next-line @typescript-eslint/no-extraneous-class
class Logger {
    private static instance: winston.Logger;

    private constructor() {
        Logger.instance = winston.createLogger({
            level: 'info',
            format: winston.format.combine(
              winston.format.timestamp(),
              winston.format.json()
            ),
            defaultMeta: { service: 'ewegen-bff' },
            transports: [
              // Console transport - logs all messages
              new winston.transports.Console({
                format: winston.format.combine(
                  winston.format.colorize(),
                  winston.format.simple()
                )
              }),
              // Access log transport - standard server notation in JSON format
              new DailyRotateFile({
                filename: path.join(__dirname, '../../logs/access-%DATE%.log'),
                datePattern: 'YYYY-MM-DD',
                maxSize: '20m',
                maxFiles: '14d',
                format: winston.format.combine(
                  winston.format.timestamp(),
                  winston.format.json()
                )
              }),
              // Error log transport - error messages in JSON format
              new DailyRotateFile({
                filename: path.join(__dirname, '../../logs/error-%DATE%.log'),
                datePattern: 'YYYY-MM-DD',
                maxSize: '20m',
                maxFiles: '14d',
                level: 'error',
                format: winston.format.combine(
                  winston.format.timestamp(),
                  winston.format.json()
                )
              })
            ]
        });
    }

    public static getInstance(): winston.Logger {
        if (!Logger.instance) {
            new Logger();
        }
        return Logger.instance;
    }
}

export default Logger;
