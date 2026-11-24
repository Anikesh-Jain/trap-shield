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

const isProduction = (process.env.NODE_ENV || 'development') === 'production';

/**
 * Approved production frontend origins
 */
export const DEFAULT_PRODUCTION_ORIGINS = Object.freeze([
  'https://trap-shield.vercel.app',
  'https://trap-shield-r0gpwye6f-anixora-tech.vercel.app',
]);

/**
 * Normalizes and parses comma- or array-separated origin strings.
 * Trims whitespace and strips any trailing slashes.
 *
 * @param {string|string[]} originInput
 * @returns {string[]}
 */
export function parseOrigins(originInput) {
  if (!originInput) return [];
  const items = Array.isArray(originInput) ? originInput : String(originInput).split(',');
  return items
    .map((item) => item.trim().replace(/\/+$/, ''))
    .filter((item) => item.length > 0);
}

/**
 * Resolves the active list of allowed CORS origins based on environment and configuration.
 *
 * In production:
 *   - Parses any configured origins from CLIENT_ORIGIN
 *   - Ensures verified production origins are always included
 *   - Preserves localhost:3000 for development only (strictly excluded from production)
 *
 * In development:
 *   - Includes localhost:3000 and verified production origins
 *
 * @param {string|string[]} [customOriginInput]
 * @param {boolean} [isProd]
 * @returns {string[]}
 */
export function resolveAllowedOrigins(customOriginInput = process.env.CLIENT_ORIGIN, isProd = isProduction) {
  const customList = parseOrigins(customOriginInput);

  if (isProd) {
    const merged = new Set([...customList, ...DEFAULT_PRODUCTION_ORIGINS]);
    return Array.from(merged);
  }

  const merged = new Set([
    ...customList,
    ...DEFAULT_PRODUCTION_ORIGINS,
    'http://localhost:3000',
  ]);
  return Array.from(merged);
}

const resolvedClientOrigins = resolveAllowedOrigins(process.env.CLIENT_ORIGIN, isProduction);
const resolvedClientOriginString = process.env.CLIENT_ORIGIN || resolvedClientOrigins.join(',');

export const env = Object.freeze({
  NODE_ENV: process.env.NODE_ENV || 'development',
  PORT: parseInt(process.env.PORT, 10) || 5000,
  CLIENT_ORIGIN: resolvedClientOriginString,
  CLIENT_ORIGINS: Object.freeze(resolvedClientOrigins),
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
  IS_PRODUCTION: isProduction,
});
