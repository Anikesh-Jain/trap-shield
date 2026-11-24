/**
 * TRAPSHIELD Scan Controller
 * 
 * Handles threat analysis requests and dispatches to detection service.
 */

import { executeScan } from '../services/detectionService.js';
import { successResponse } from '../utils/apiResponse.js';

export async function handleScan(req, res, next) {
  try {
    const { type, input } = req.body;
    const userId = req.user?._id || null;
    const isGuest = !userId;

    const result = await executeScan({
      type,
      input,
      userId,
      isGuest,
    });

    return successResponse(
      res,
      result,
      'Threat analysis completed successfully',
      200,
      { analysisType: type }
    );
  } catch (err) {
    return next(err);
  }
}

