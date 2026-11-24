/**
 * TRAPSHIELD Transparency & Privacy Controller
 * 
 * Publicly discloses data retention policies, admin access rights,
 * and zero-network URL inspection guarantees.
 */

import { successResponse } from '../utils/apiResponse.js';

export function getPrivacyPolicy(req, res) {
  const policy = {
    version: '1.0.0',
    effectiveDate: '2026-11-24',
    guarantees: [
      {
        scope: 'GUEST_SCANS',
        policy: 'Zero Data Retention',
        disclosure:
          'Unauthenticated guest scans do not require an account. Submitted message texts, URLs, and job descriptions are NEVER stored in the database or persistent log files. Only non-sensitive statistical metadata is recorded for aggregate performance metrics.',
      },
      {
        scope: 'REGISTERED_USER_SCANS',
        policy: '90-Day Automatic Expiration (TTL)',
        disclosure:
          'For authenticated registered users, submitted contents and detection results are stored in their personal scan history. A MongoDB TTL index automatically purges all scan records exactly 90 days after creation. Users may also manually delete individual scan records at any time.',
      },
      {
        scope: 'ADMINISTRATIVE_ACCESS_DISCLOSURE',
        policy: 'Authorized Forensic Review',
        disclosure:
          'Platform administrators possess authorized server-side access to review registered users saved scan contents and analysis results for safety investigation, support, and platform abuse prevention. All administrator viewing actions are permanently recorded in an immutable audit log.',
      },
      {
        scope: 'OFFLINE_ANALYSIS_INTEGRITY',
        policy: 'Zero External Transmission',
        disclosure:
          'TRAPSHIELD detection runs 100% offline. Submitted URLs are inspected structurally and lexically. TRAPSHIELD never visits, fetches, resolves, or transmits submitted URLs or texts to external third-party servers.',
      },
    ],
  };

  return successResponse(res, policy, 'TRAPSHIELD privacy and data retention policy');
}

