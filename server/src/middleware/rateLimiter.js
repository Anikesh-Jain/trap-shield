/**
 * TRAPSHIELD Rate Limiting Middleware
 * 
 * Provides defense-in-depth against denial-of-service and brute force abuse.
 */

import rateLimit from 'express-rate-limit';
import { env } from '../config/env.js';
import { errorResponse } from '../utils/apiResponse.js';

/**
 * General API rate limiter
 */
export const generalLimiter = rateLimit({
  windowMs: env.RATE_LIMIT_WINDOW_MS,
  max: env.RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    return errorResponse(
      res,
      'Too many requests from this IP address. Please try again later.',
      429,
      'RATE_LIMIT_EXCEEDED'
    );
  },
});

/**
 * Scan endpoint specific rate limiter (stricter limit for heavy analysis payloads)
 */
export const scanLimiter = rateLimit({
  windowMs: env.RATE_LIMIT_WINDOW_MS,
  max: env.SCAN_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    return errorResponse(
      res,
      'Scan rate limit exceeded. Please wait a few minutes before submitting additional scans.',
      429,
      'SCAN_RATE_LIMIT_EXCEEDED'
    );
  },
});

/**
 * Auth endpoint specific rate limiter (protects against login/register brute-force)
 */
export const authLimiter = rateLimit({
  windowMs: env.RATE_LIMIT_WINDOW_MS,
  max: env.AUTH_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    return errorResponse(
      res,
      'Too many authentication attempts. Please wait before trying again.',
      429,
      'AUTH_RATE_LIMIT_EXCEEDED'
    );
  },
});
