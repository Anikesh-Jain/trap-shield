/**
 * Standardized API Response Utilities
 */

export function successResponse(res, data, message = 'Success', statusCode = 200, meta = {}) {
  return res.status(statusCode).json({
    success: true,
    statusCode,
    message,
    data,
    meta: {
      timestamp: new Date().toISOString(),
      ...meta,
    },
  });
}

export function errorResponse(res, message = 'Internal Server Error', statusCode = 500, errorCode = 'INTERNAL_ERROR', details = null) {
  const body = {
    success: false,
    statusCode,
    errorCode,
    message,
    timestamp: new Date().toISOString(),
  };

  if (details && typeof details === 'object') {
    body.details = details;
  }

  return res.status(statusCode).json(body);
}

