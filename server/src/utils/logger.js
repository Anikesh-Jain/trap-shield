/**
 * Production-minded Safe Logger for TRAPSHIELD
 * 
 * SECURITY MANDATE:
 * Never logs sensitive credentials, passwords, auth tokens, or submitted scan payloads.
 */

import { env } from '../config/env.js';

function formatTimestamp() {
  return new Date().toISOString();
}

export const logger = {
  info: (message, meta = {}) => {
    const logObj = { level: 'INFO', timestamp: formatTimestamp(), message, ...meta };
    if (env.IS_PRODUCTION) {
      console.log(JSON.stringify(logObj));
    } else {
      console.log(`[${logObj.timestamp}] [INFO] ${message}`, Object.keys(meta).length ? meta : '');
    }
  },

  warn: (message, meta = {}) => {
    const logObj = { level: 'WARN', timestamp: formatTimestamp(), message, ...meta };
    if (env.IS_PRODUCTION) {
      console.warn(JSON.stringify(logObj));
    } else {
      console.warn(`[${logObj.timestamp}] [WARN] ${message}`, Object.keys(meta).length ? meta : '');
    }
  },

  error: (message, error = null, meta = {}) => {
    const errorDetails = error instanceof Error
      ? { name: error.name, message: error.message }
      : error;

    const logObj = {
      level: 'ERROR',
      timestamp: formatTimestamp(),
      message,
      error: errorDetails,
      ...meta,
    };

    if (env.IS_PRODUCTION) {
      console.error(JSON.stringify(logObj));
    } else {
      console.error(`[${logObj.timestamp}] [ERROR] ${message}`, errorDetails || '', Object.keys(meta).length ? meta : '');
    }
  },

  debug: (message, meta = {}) => {
    if (!env.IS_PRODUCTION) {
      console.debug(`[${formatTimestamp()}] [DEBUG] ${message}`, Object.keys(meta).length ? meta : '');
    }
  },
};

