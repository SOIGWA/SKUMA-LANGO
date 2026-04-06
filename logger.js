/**
 * sukuma-lango/backend/src/utils/logger.js
 * Centralised Winston logger with daily log rotation.
 * Outputs JSON for easy forensic ingestion.
 */

'use strict';

const { createLogger, format, transports } = require('winston');
require('winston-daily-rotate-file');
const path = require('path');

const LOG_DIR  = process.env.LOG_DIR || './logs';
const LOG_LEVEL = process.env.LOG_LEVEL || 'info';

// ---------------------------------------------------------------------------
// Custom format: timestamp + level + message + metadata
// ---------------------------------------------------------------------------
const customFormat = format.combine(
  format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
  format.errors({ stack: true }),
  format.json()
);

// ---------------------------------------------------------------------------
// Rotating file transports (one for all, one for errors only)
// ---------------------------------------------------------------------------
const dailyAll = new transports.DailyRotateFile({
  filename:     path.join(LOG_DIR, 'sukuma-lango-%DATE%.log'),
  datePattern:  'YYYY-MM-DD',
  maxSize:      '20m',
  maxFiles:     '30d',
  zippedArchive: true,
  format:       customFormat,
});

const dailyError = new transports.DailyRotateFile({
  level:        'error',
  filename:     path.join(LOG_DIR, 'sukuma-lango-errors-%DATE%.log'),
  datePattern:  'YYYY-MM-DD',
  maxSize:      '20m',
  maxFiles:     '90d',    // Retain error logs longer for forensics
  zippedArchive: true,
  format:       customFormat,
});

// ---------------------------------------------------------------------------
// Assemble logger
// ---------------------------------------------------------------------------
const logger = createLogger({
  level:      LOG_LEVEL,
  format:     customFormat,
  transports: [
    dailyAll,
    dailyError,
    // Console transport in development
    ...(process.env.NODE_ENV !== 'production'
      ? [new transports.Console({
          format: format.combine(
            format.colorize(),
            format.printf(({ timestamp, level, message, ...meta }) =>
              `[${timestamp}] ${level}: ${message} ${
                Object.keys(meta).length ? JSON.stringify(meta) : ''
              }`
            )
          ),
        })]
      : []),
  ],
  // Prevent crash on unhandled exceptions in logger itself
  exitOnError: false,
});

module.exports = logger;
