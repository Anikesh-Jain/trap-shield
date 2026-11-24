/**
 * TRAPSHIELD Request Validation Middleware
 * 
 * SECURITY MANDATE:
 * Never logs or reveals submitted scan text in validation error messages or logs.
 */

import { ANALYSIS_TYPES } from '../services/detectionService.js';
import { errorResponse } from '../utils/apiResponse.js';

const VALID_TYPES = Object.values(ANALYSIS_TYPES);
const MAX_INPUT_LENGTH = 50000; // 50 KB text payload ceiling to prevent DoS

export function validateScanRequest(req, res, next) {
  const { type, input } = req.body || {};

  if (!type || typeof type !== 'string') {
    return errorResponse(
      res,
      `Field "type" is required and must be one of: ${VALID_TYPES.join(', ')}`,
      400,
      'INVALID_ANALYSIS_TYPE'
    );
  }

  const normalizedType = type.trim().toUpperCase();
  if (!VALID_TYPES.includes(normalizedType)) {
    return errorResponse(
      res,
      `Invalid analysis type: "${type}". Expected one of: ${VALID_TYPES.join(', ')}`,
      400,
      'INVALID_ANALYSIS_TYPE'
    );
  }

  if (typeof input !== 'string') {
    return errorResponse(
      res,
      'Field "input" is required and must be a string.',
      400,
      'INVALID_INPUT'
    );
  }

  if (input.trim().length === 0) {
    return errorResponse(
      res,
      'Field "input" cannot be empty.',
      400,
      'EMPTY_INPUT'
    );
  }

  if (input.length > MAX_INPUT_LENGTH) {
    return errorResponse(
      res,
      `Input payload exceeds maximum allowed size of ${MAX_INPUT_LENGTH} characters.`,
      413,
      'PAYLOAD_TOO_LARGE'
    );
  }

  // Attach normalized type to request
  req.body.type = normalizedType;
  return next();
}

