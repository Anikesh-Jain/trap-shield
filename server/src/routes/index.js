/**
 * TRAPSHIELD API v1 Router
 */

import { Router } from 'express';
import healthRoutes from './healthRoutes.js';
import scanRoutes from './scanRoutes.js';
import authRoutes from './authRoutes.js';
import adminRoutes from './adminRoutes.js';
import privacyRoutes from './privacyRoutes.js';

const router = Router();

router.use('/health', healthRoutes);
router.use('/scan', scanRoutes);
router.use('/auth', authRoutes);
router.use('/admin', adminRoutes);
router.use('/privacy', privacyRoutes);

export default router;
