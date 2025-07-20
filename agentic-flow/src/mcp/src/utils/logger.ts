/**
 * Logger utility for MCP server
 */

import winston from 'winston';
import chalk from 'chalk';

// Create custom log format
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.printf(({ level, message, timestamp, stack }) => {
    const colorizedLevel = colorizeLevel(level);
    const formattedMessage = stack || message;
    return `${chalk.gray(timestamp)} [${colorizedLevel}] ${formattedMessage}`;
  })
);

// Colorize log levels
function colorizeLevel(level: string): string {
  switch (level) {
    case 'error':
      return chalk.red('ERROR');
    case 'warn':
      return chalk.yellow('WARN');
    case 'info':
      return chalk.blue('INFO');
    case 'debug':
      return chalk.green('DEBUG');
    default:
      return level.toUpperCase();
  }
}

// Create logger instance
export const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: logFormat,
  defaultMeta: { service: 'agentic-flow-mcp' },
  transports: [
    // Console transport
    new winston.transports.Console({
      format: logFormat
    }),
    
    // File transport for errors
    new winston.transports.File({
      filename: 'logs/error.log',
      level: 'error',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      )
    }),
    
    // File transport for all logs
    new winston.transports.File({
      filename: 'logs/combined.log',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      )
    })
  ]
});

// Development logging
if (process.env.NODE_ENV === 'development') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
  }));
}

// Handle uncaught exceptions
logger.exceptions.handle(
  new winston.transports.File({ filename: 'logs/exceptions.log' })
);

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

export default logger;