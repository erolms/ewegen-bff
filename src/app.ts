// @ts-check

import express from 'express';
import path from 'path';
import cookieParser from 'cookie-parser';
import morgan from 'morgan';
import Logger from './middlewares/logger';
import { errorHandler } from './middlewares/error-middleware';
import indexRouter from './routes/index';
import authRoutes from './routes/auth';
import protectedRoutes from './routes/protected';

// Import central logger instance
const logger = Logger.getInstance();

const app = express();

// Use Morgan for HTTP request logging, output to logger
app.use(morgan('combined', {
  skip: function (_req, res) { return res.statusCode > 399 },
  stream: { write: (message: string) => logger.info(message.trim()) },
}))
app.use(morgan('combined', {
  skip: function (_req, res) { return res.statusCode < 400 },
  stream: { write: (message: string) => logger.error(message.trim()) },
}))

app.disable("x-powered-by");
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Error handling middleware
app.use(errorHandler);

// Application routes
app.use('/', indexRouter);
app.use('/auth', authRoutes);
app.use('/protected', protectedRoutes);

// Log application startup
logger.info('eWegen BFF application started');

export default app;
