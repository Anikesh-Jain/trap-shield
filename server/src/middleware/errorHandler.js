/**
 * TRAPSHIELD Centralized Error Handling Middleware
 * 
 * SECURITY MANDATE:
 * Never exposes internal stack traces or database driver specifics to API clients.
 */

import { errorResponse } from '../utils/apiResponse.js';
import { logger } from '../utils/logger.js';
import { env } from '../config/env.js';

export function notFoundHandler(req, res) {
  return errorResponse(
    res,
    `Cannot ${req.method} ${req.originalUrl} - Endpoint not found`,
    404,
    'ROUTE_NOT_FOUND'
  );
}

export function errorHandler(err, req, res, next) {
  // If headers already sent, delegate to Express default handler
  if (res.headersSent) {
    return next(err);
  }

  // Log error safely server-side
  logger.error('Unhandled request exception', err, {
    method: req.method,
    path: req.originalUrl,
  });

  // Handle specific known error classes
  if (err.name === 'SyntaxError' && err.status === 400 && 'body' in err) {
    return errorResponse(res, 'Malformed JSON in request body', 400, 'BAD_REQUEST');
  }

  if (err.message && err.message.includes('CORS')) {
    return errorResponse(res, err.message, 403, 'CORS_FORBIDDEN');
  }

  const statusCode = err.statusCode || err.status || 500;
  const message = env.IS_PRODUCTION && statusCode === 500
    ? 'Internal Server Error'
    : (err.message || 'An unexpected server error occurred');

  return errorResponse(
    res,
    message,
    statusCode,
    err.errorCode || err.code || 'INTERNAL_ERROR'
  );
}

