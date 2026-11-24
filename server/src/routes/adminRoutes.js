/**
 * TRAPSHIELD Admin Routes
 * 
 * SERVER-SIDE AUTHORIZATION:
 * Every endpoint requires active user session with role: 'admin'.
 */

import { Router } from 'express';
import {
  listUsers,
  getUserScans,
  updateUserStatus,
  getPlatformStats,
  getAuditLogs,
} from '../controllers/adminController.js';
import { requireAuth, requireAdmin } from '../middleware/auth.js';

const router = Router();

// Apply auth & admin requirement across all admin sub-routes
router.use(requireAuth, requireAdmin);

router.get('/users', listUsers);
router.get('/users/:id/scans', getUserScans);
router.patch('/users/:id/status', updateUserStatus);
router.get('/stats', getPlatformStats);
router.get('/audit-logs', getAuditLogs);

export default router;

