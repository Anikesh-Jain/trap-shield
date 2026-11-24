/**
 * TRAPSHIELD Authentication & Authorization Middleware
 * 
 * Verifies HTTP-only session cookies and enforces role-based access control.
 */

import { verifyToken } from '../utils/token.js';
import { User } from '../models/User.js';
import { env } from '../config/env.js';
import { errorResponse } from '../utils/apiResponse.js';

function extractToken(req) {
  // 1. Primary: HTTP-only session cookie
  if (req.cookies && req.cookies[env.COOKIE_NAME]) {
    return req.cookies[env.COOKIE_NAME];
  }

  // 2. Secondary fallback: Authorization Bearer header
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7).trim();
  }

  return null;
}

/**
 * Creates authentication middleware
 * @param {boolean} optional - If true, unauthenticated requests proceed with req.user = null
 */
function createAuthMiddleware(optional = false) {
  return async (req, res, next) => {
    const token = extractToken(req);

    if (!token) {
      if (optional) {
        req.user = null;
        return next();
      }
      return errorResponse(res, 'Authentication required to access this resource', 401, 'AUTH_REQUIRED');
    }

    const decoded = verifyToken(token);
    if (!decoded || !decoded.id) {
      if (optional) {
        req.user = null;
        return next();
      }
      return errorResponse(res, 'Session is invalid or has expired. Please log in again.', 401, 'SESSION_EXPIRED');
    }

    try {
      const user = await User.findById(decoded.id);

      if (!user) {
        if (optional) {
          req.user = null;
          return next();
        }
        return errorResponse(res, 'User account no longer exists', 401, 'USER_NOT_FOUND');
      }

      if (!user.isActive) {
        return errorResponse(
          res,
          'Account has been suspended. Please contact administrator.',
          403,
          'ACCOUNT_SUSPENDED'
        );
      }

      // Check tokenVersion for global session invalidation
      if (decoded.tokenVersion !== undefined && decoded.tokenVersion !== user.tokenVersion) {
        return errorResponse(res, 'Session has been invalidated. Please log in again.', 401, 'SESSION_INVALIDATED');
      }

      req.user = user;
      return next();
    } catch (err) {
      if (optional) {
        req.user = null;
        return next();
      }
      return next(err);
    }
  };
}

export const requireAuth = createAuthMiddleware(false);
export const optionalAuth = createAuthMiddleware(true);

/**
 * Admin authorization middleware
 * Must be preceded by requireAuth
 */
export function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return errorResponse(res, 'Administrator access required', 403, 'FORBIDDEN_ADMIN_ONLY');
  }
  return next();
}

