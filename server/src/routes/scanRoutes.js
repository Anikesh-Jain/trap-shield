/**
 * TRAPSHIELD Scan & History Routes
 */

import { Router } from 'express';
import { handleScan } from '../controllers/scanController.js';
import { getScanHistory, getScanById, deleteScanById } from '../controllers/scanHistoryController.js';
import { scanLimiter } from '../middleware/rateLimiter.js';
import { validateScanRequest } from '../middleware/validateRequest.js';
import { optionalAuth, requireAuth } from '../middleware/auth.js';

const router = Router();

// Scanning endpoint: guests can scan anonymously; authenticated scans are saved to personal history
router.post('/', scanLimiter, optionalAuth, validateScanRequest, handleScan);

// Registered user personal history endpoints (strictly scoped by req.user._id)
router.get('/history', requireAuth, getScanHistory);
router.get('/history/:id', requireAuth, getScanById);
router.delete('/history/:id', requireAuth, deleteScanById);

export default router;
