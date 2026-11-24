/**
 * TRAPSHIELD Authentication Token & Cookie Utilities
 * 
 * SECURITY MANDATE:
 * - Issues cryptographically signed JSON Web Tokens.
 * - Enforces HTTP-only, SameSite, and Secure flags on auth cookies.
 * - Never transmits tokens in plain JSON bodies when cookies are utilized.
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

export function setAuthCookie(res, token) {
  res.cookie(env.COOKIE_NAME, token, {
    httpOnly: true,
    secure: env.IS_PRODUCTION,
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    path: '/',
  });
}

export function clearAuthCookie(res) {
  res.clearCookie(env.COOKIE_NAME, {
    httpOnly: true,
    secure: env.IS_PRODUCTION,
    sameSite: 'lax',
    path: '/',
  });
}

