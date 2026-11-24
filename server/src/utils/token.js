/**
 * TRAPSHIELD Authentication Token & Cookie Utilities
 * 
 * SECURITY MANDATE:
 * - Issues cryptographically signed JSON Web Tokens.
 * - Enforces HTTP-only, SameSite, and Secure flags on auth cookies.
 * - In production (cross-site frontend on Vercel + backend on Render), sets
 *   SameSite=None, Secure=true, and Partitioned=true so cookies are stored
 *   and sent on cross-site credentialed requests.
 * - In development (localhost), sets SameSite=Lax and Secure=false to support
 *   standard local HTTP development.
 */

import jwt from 'jsonwebtoken';
import { env } from '../config/env.js';

export function generateToken(user) {
  const payload = {
    id: user._id.toString(),
    role: user.role,
    tokenVersion: user.tokenVersion || 0,
  };

  return jwt.sign(payload, env.JWT_SECRET, {
    expiresIn: env.JWT_EXPIRES_IN,
  });
}

export function verifyToken(token) {
  try {
    return jwt.verify(token, env.JWT_SECRET);
  } catch {
    return null;
  }
}

/**
 * Returns security-hardened cookie options tailored to runtime environment.
 *
 * Cross-Site Production Requirements (e.g. Vercel frontend -> Render backend):
 * - sameSite: 'none' (allows cross-site fetch with credentials)
 * - secure: true (mandatory when SameSite=None)
 * - partitioned: true (CHIPS standard for modern browser cookie isolation)
 * - httpOnly: true (prevents XSS exfiltration)
 *
 * @param {object} [options]
 * @returns {object}
 */
export function getAuthCookieOptions(options = {}) {
  const isProd = options.isProduction !== undefined ? options.isProduction : env.IS_PRODUCTION;

  return {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    partitioned: isProd,
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    path: '/',
    ...options,
  };
}

export function setAuthCookie(res, token, customOptions = {}) {
  const cookieOptions = getAuthCookieOptions(customOptions);
  res.cookie(env.COOKIE_NAME, token, cookieOptions);
}

export function clearAuthCookie(res, customOptions = {}) {
  const cookieOptions = getAuthCookieOptions(customOptions);
  delete cookieOptions.maxAge;
  res.clearCookie(env.COOKIE_NAME, cookieOptions);
}
