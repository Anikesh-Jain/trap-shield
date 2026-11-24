/**
 * TRAPSHIELD Server Environment Configuration
 */

import dotenv from 'dotenv';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Load environment variables from server/.env if present, falling back to root .env
const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.resolve(__dirname, '../../../server/.env') });
dotenv.config(); // fallback to root .env

export const env = Object.freeze({
  NODE_ENV: process.env.NODE_ENV || 'development',
  PORT: parseInt(process.env.PORT, 10) || 5000,
  CLIENT_ORIGIN: process.env.CLIENT_ORIGIN || 'http://localhost:3000',
  MONGODB_URI: process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/trapshield',
  JWT_SECRET: process.env.JWT_SECRET || 'trapshield-dev-jwt-super-secret-key-change-in-prod-2026',
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '7d',
  COOKIE_NAME: process.env.COOKIE_NAME || 'trapshield_token',
  ADMIN_EMAIL: process.env.ADMIN_EMAIL || 'admin@trapshield.local',
  ADMIN_PASSWORD: process.env.ADMIN_PASSWORD || '',
  RATE_LIMIT_WINDOW_MS: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 15 * 60 * 1000, // 15 mins
  RATE_LIMIT_MAX: parseInt(process.env.RATE_LIMIT_MAX, 10) || 100,
  SCAN_RATE_LIMIT_MAX: parseInt(process.env.SCAN_RATE_LIMIT_MAX, 10) || 30,
  AUTH_RATE_LIMIT_MAX: (process.env.NODE_ENV === 'test') ? 1000 : (parseInt(process.env.AUTH_RATE_LIMIT_MAX, 10) || 30),
  DEV_CUSTOM_DNS: process.env.DEV_CUSTOM_DNS !== 'false',
  DEV_DNS_SERVERS: process.env.DEV_DNS_SERVERS ? process.env.DEV_DNS_SERVERS.split(',').map(s => s.trim()) : null,
  IS_PRODUCTION: (process.env.NODE_ENV || 'development') === 'production',
});
