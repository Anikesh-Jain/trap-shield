/**
 * TRAPSHIELD Security Middleware
 * 
 * Configures Helmet security headers and CORS restrictions.
 */

import helmet from 'helmet';
import cors from 'cors';
import { env } from '../config/env.js';

export function configureSecurityHeaders() {
  return helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        fontSrc: ["'self'", 'https:', 'data:'],
        imgSrc: ["'self'", 'data:', 'https:'],
        scriptSrc: ["'self'"],
        connectSrc: ["'self'", env.CLIENT_ORIGIN],
      },
    },
    crossOriginEmbedderPolicy: false,
  });
}

export function configureCors() {
  const allowedOrigins = env.CLIENT_ORIGIN.split(',').map(o => o.trim());

  return cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (e.g. server-to-server or curl/Postman in dev)
      if (!origin) {
        return callback(null, true);
      }

      if (allowedOrigins.includes(origin) || (!env.IS_PRODUCTION && origin.startsWith('http://localhost:'))) {
        return callback(null, true);
      }

      return callback(new Error(`Origin ${origin} not allowed by CORS policy`));
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    credentials: true,
    maxAge: 86400, // 24 hours
  });
}

