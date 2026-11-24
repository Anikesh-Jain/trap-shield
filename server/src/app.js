/**
 * TRAPSHIELD Express Application Configuration
 */

import express from 'express';
import cookieParser from 'cookie-parser';
import { configureSecurityHeaders, configureCors } from './middleware/security.js';
import { generalLimiter } from './middleware/rateLimiter.js';
import { notFoundHandler, errorHandler } from './middleware/errorHandler.js';
import apiV1Routes from './routes/index.js';

export const app = express();

// Trust reverse proxy (Render, Cloudflare, Heroku) for HTTPS detection and accurate client IP
app.set('trust proxy', 1);

// 1. Security & Protection Middleware
app.use(configureSecurityHeaders());
app.use(configureCors());

// 2. Cookie & Request Body Parsing Middleware
app.use(cookieParser());
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));

// 3. Global Rate Limiter
app.use(generalLimiter);

// 4. Root Service Ping
app.get('/', (req, res) => {
  res.status(200).json({
    name: 'TRAPSHIELD Detection API',
    status: 'operational',
    documentation: '/api/v1/health',
    privacy: '/api/v1/privacy',
    version: 'v1',
  });
});

// 5. Versioned API Routes
app.use('/api/v1', apiV1Routes);

// 6. 404 & Centralized Error Handlers
app.use(notFoundHandler);
app.use(errorHandler);
