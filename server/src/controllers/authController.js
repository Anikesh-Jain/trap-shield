/**
 * TRAPSHIELD Authentication Controller
 */

import { register, login } from '../services/authService.js';
import { setAuthCookie, clearAuthCookie } from '../utils/token.js';
import { successResponse } from '../utils/apiResponse.js';

export async function handleRegister(req, res, next) {
  try {
    const { email, password } = req.body || {};
    const { user, token } = await register({ email, password });

    setAuthCookie(res, token);
    return successResponse(res, { user }, 'User registration successful', 201);
  } catch (err) {
    return next(err);
  }
}

export async function handleLogin(req, res, next) {
  try {
    const { email, password } = req.body || {};
    const { user, token } = await login({ email, password });

    setAuthCookie(res, token);
    return successResponse(res, { user }, 'Login successful', 200);
  } catch (err) {
    return next(err);
  }
}

export function handleLogout(req, res) {
  clearAuthCookie(res);
  return successResponse(res, null, 'Logged out successfully', 200);
}

export function handleGetCurrentUser(req, res) {
  return successResponse(res, { user: req.user.toSafeJSON() }, 'Current user profile', 200);
}

