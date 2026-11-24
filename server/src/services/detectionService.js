/**
 * TRAPSHIELD Server Detection Service
 * 
 * Server-side integration boundary calling the core detection engine.
 * 
 * CRITICAL PRIVACY & DATA RETENTION RULES:
 * 1. Guest scans: NEVER persist submitted text, raw URLs, or payloads.
 *    Only non-sensitive statistical metadata is recorded in ScanAudit.
 * 2. Registered users: Save submitted text and analysis to Scan collection
 *    for user's personal history, auto-expiring in 90 days via TTL index.
 * 3. 100% offline inspection. NEVER visits, fetches, or resolves URLs.
 */

import { analyze, ANALYSIS_TYPES } from '../../../src/detection/index.js';
import { isDatabaseConnected } from '../config/db.js';
import { Scan } from '../models/Scan.js';
import { ScanAudit } from '../models/ScanAudit.js';
import { logger } from '../utils/logger.js';

export { ANALYSIS_TYPES };

/**
 * Executes threat analysis using the unified detection engine.
 * 
 * @param {object} params
 * @param {string} params.type - ANALYSIS_TYPES enum ('MESSAGE', 'URL', 'JOB_OFFER')
 * @param {string} params.input - Raw content or URL string (analyzed offline)
 * @param {string|null} [params.userId] - Optional authenticated user ID
 * @param {boolean} [params.isGuest] - Whether the scan is from an unauthenticated guest
 * @returns {Promise<object>} Detection engine result
 */
export async function executeScan({ type, input, userId = null, isGuest = true }) {
  // Execute pure offline analysis
  const scanResult = analyze({ type, input });

  if (isDatabaseConnected()) {
    try {
      if (!isGuest && userId) {
        // REGISTERED USER: Save scan content and analysis for user's personal history
        // Automatically deleted after 90 days via MongoDB TTL index
        const savedScan = await Scan.create({
          userId,
          analysisType: type,
          submittedContent: input,
          riskScore: scanResult.riskScore,
          riskClassification: scanResult.riskClassification,
          scoringMetadata: scanResult.scoringMetadata,
          detectedIndicators: scanResult.detectedIndicators,
          evidence: scanResult.evidence,
          explanations: scanResult.explanations,
          recommendedActions: scanResult.recommendedActions,
        });

        // Attach saved record ID to response for user's reference
        scanResult.savedScanId = savedScan._id.toString();
      }

      // Record non-sensitive statistical metadata for aggregate metrics
      const detectedIds = (scanResult.detectedIndicators || []).map(ind => ind.id);
      await ScanAudit.create({
        analysisType: type,
        riskScore: scanResult.riskScore,
        riskLevel: scanResult.riskClassification ? scanResult.riskClassification.level : 'LOW',
        indicatorCount: detectedIds.length,
        detectedIndicatorIds: detectedIds,
        isGuest,
        userId: userId || null,
      });
    } catch (dbErr) {
      // Non-blocking: DB save failures must never crash scan response
      logger.warn('Failed to record scan in database', { reason: dbErr.message });
    }
  }

  return scanResult;
}
