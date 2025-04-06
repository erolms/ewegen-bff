// @ts-check

import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import cookieParser from 'cookie-parser';
import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import morgan from 'morgan';
import { createStream } from 'rotating-file-stream';
import indexRouter from './routes/index';

// Configure Winston logger
const logger = winston.createLogger({
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
      filename: path.join(__dirname, '../logs/access-%DATE%.log'),
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
      filename: path.join(__dirname, '../logs/error-%DATE%.log'),
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

// Create a stream for Morgan to use with Winston
const accessLogStream = createStream('access.log', {
  interval: '1d',
  path: path.join(__dirname, '../logs'),
  compress: 'gzip'
});

const app = express();

// Use Morgan for HTTP request logging, output to Winston
app.use(morgan('combined', { stream: { write: (message: string) => logger.info(message.trim()) } }));

// Error handling middleware
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  logger.error('Error occurred', { error: err.message, stack: err.stack });
  res.status(500).json({ error: 'Internal Server Error' });
});

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', indexRouter);

// Log application startup
logger.info('eWegen BFF application started');

export default app;
