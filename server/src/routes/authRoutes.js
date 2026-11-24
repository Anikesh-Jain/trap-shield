/**
 * TRAPSHIELD Authentication Routes
 */

import { Router } from 'express';
import { handleRegister, handleLogin, handleLogout, handleGetCurrentUser } from '../controllers/authController.js';
import { requireAuth } from '../middleware/auth.js';
import { authLimiter } from '../middleware/rateLimiter.js';

const router = Router();

router.post('/register', authLimiter, handleRegister);
router.post('/login', authLimiter, handleLogin);
router.post('/logout', handleLogout);
router.get('/me', requireAuth, handleGetCurrentUser);

export default router;

