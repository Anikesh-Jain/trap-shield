/**
 * TRAPSHIELD Privacy & Disclosure Routes
 */

import { Router } from 'express';
import { getPrivacyPolicy } from '../controllers/privacyController.js';

const router = Router();

router.get('/', getPrivacyPolicy);

export default router;

