/**
 * TRAPSHIELD Security Middleware
 *
 * Configures Helmet security headers and CORS restrictions.
 */

import helmet from 'helmet';
import cors from 'cors';
import { env } from '../config/env.js';

/**
 * Configures Helmet security headers with an explicit Content Security Policy.
 * Connect-src is populated from the configured client origins.
 */
export function configureSecurityHeaders() {
  const connectSources = ["'self'", ...env.CLIENT_ORIGINS];

  return helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        fontSrc: ["'self'", 'https:', 'data:'],
        imgSrc: ["'self'", 'data:', 'https:'],
        scriptSrc: ["'self'"],
        connectSrc: connectSources,
      },
    },
    crossOriginEmbedderPolicy: false,
  });
}

/**
 * Configures Cross-Origin Resource Sharing (CORS) with strict origin whitelisting,
 * credential support, and full preflight handling.
 *
 * SAFETY MANDATES:
 * 1. Never uses wildcard origins ('*') when credentials are enabled.
 * 2. In production, permits configured origins and verified production frontend deployments.
 * 3. Preserves localhost:3000 and 127.0.0.1 for development environments only.
 * 4. Supports OPTIONS preflight requests for all application HTTP methods.
 *
 * @param {object} [options]
 * @param {boolean} [options.isProduction]
 * @param {string[]} [options.allowedOrigins]
 */
export function configureCors(options = {}) {
  const isProd = options.isProduction !== undefined ? options.isProduction : env.IS_PRODUCTION;
  const allowedOrigins = options.allowedOrigins || env.CLIENT_ORIGINS;

  return cors({
    origin: (origin, callback) => {
      // 1. Allow requests with no origin (e.g. server-to-server, curl, Postman, mobile)
      if (!origin) {
        return callback(null, true);
      }

      const normalizedOrigin = origin.trim().replace(/\/+$/, '');

      // 2. Exact match against allowed origins list
      if (allowedOrigins.includes(normalizedOrigin)) {
        return callback(null, true);
      }

      // 3. Preserve localhost and 127.0.0.1 for development environments ONLY
      if (!isProd && (
        normalizedOrigin.startsWith('http://localhost:') ||
        normalizedOrigin.startsWith('http://127.0.0.1:') ||
        normalizedOrigin === 'http://localhost' ||
        normalizedOrigin === 'http://127.0.0.1'
      )) {
        return callback(null, true);
      }

      // 4. Reject unauthorized origin
      return callback(new Error(`Origin ${origin} not allowed by CORS policy`));
    },
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Cookie'],
    exposedHeaders: ['Set-Cookie'],
    credentials: true,
    maxAge: 86400, // 24 hours preflight cache
  });
}
