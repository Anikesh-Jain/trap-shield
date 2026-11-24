/**
 * TRAPSHIELD Risk Classifications and Actionable Safety Recommendations
 * 
 * CRITICAL REQUIREMENTS:
 * 1. Do NOT claim the score is a probability of fraud.
 * 2. Do NOT declare a submission "safe" merely because no rules matched.
 */

import { RISK_LEVELS, SCORING_METADATA } from '../types.js';

/**
 * Maps numerical risk score (0-100) to structured classification
 * @param {number} score 
 * @returns {object}
 */
export function classifyRisk(score) {
  const boundedScore = Math.max(0, Math.min(100, Math.round(score)));

  if (boundedScore >= 71) {
    return {
      level: RISK_LEVELS.CRITICAL,
      code: 'CRITICAL_RISK',
      label: 'Critical Risk: Severe Fraud Signatures Detected',
      summary: 'Multiple high-severity scam, coercion, or credential harvesting patterns were identified. Engaging with this submission carries severe risk of financial loss or account compromise.',
    };
  }

  if (boundedScore >= 41) {
    return {
      level: RISK_LEVELS.HIGH,
      code: 'HIGH_RISK',
      label: 'High Risk: Highly Suspicious Indicators Detected',
      summary: 'Substantial deceptive indicators were identified (e.g. artificial urgency, brand spoofing, or irregular recruitment channels). Extreme caution is required.',
    };
  }

  if (boundedScore >= 16) {
    return {
      level: RISK_LEVELS.ELEVATED,
      code: 'ELEVATED_RISK',
      label: 'Elevated Risk: Anomalous Patterns Detected',
      summary: 'Several irregular patterns were detected that diverge from standard organizational communications. Independent verification is strongly advised.',
    };
  }

  // score is 0 - 15: REQUIREMENT 7: Avoid declaring safe merely because no suspicious rules matched
  return {
    level: RISK_LEVELS.LOW_INCONCLUSIVE,
    code: 'LOW_INCONCLUSIVE',
    label: 'No Suspicious Indicators Detected (Verify Independently)',
    summary: 'No recognized fraud, phishing, or scam signatures matched the current rule set. However, this does NOT certify the submission as safe or authentic. Sophisticated social engineering and zero-day campaigns may not trigger heuristic rules.',
  };
}

/**
 * Generates context-aware, actionable safety recommendations based on classification and detected categories
 * @param {object} params
 * @param {string} params.level
 * @param {Array<object>} params.detectedIndicators
 * @param {string} params.analysisType
 * @returns {string[]}
 */
export function generateRecommendedActions({ level, detectedIndicators = [], analysisType }) {
  const actions = [];
  const categories = new Set(detectedIndicators.map(i => i.category));

  if (level === RISK_LEVELS.CRITICAL || level === RISK_LEVELS.HIGH) {
    actions.push('Do NOT click any links, open attachments, or download files from this source.');
    actions.push('Do NOT transfer money, pay registration fees, or provide gift cards/cryptocurrency.');
    actions.push('Never share one-time passwords (OTP), PINs, banking credentials, or personal identification.');
    
    if (categories.has('communication_channel')) {
      actions.push('Avoid continuing conversations on private messaging channels like Telegram or WhatsApp.');
    }

    if (categories.has('impersonation') || categories.has('brand_spoofing')) {
      actions.push('Report this impersonation attempt to the legitimate organization through their official public website.');
    }

    actions.push('Block and report the sender or domain immediately.');
    return actions;
  }

  if (level === RISK_LEVELS.ELEVATED) {
    actions.push('Exercise caution: do not input personal credentials or payment details.');
    actions.push('Verify the sender or domain identity independently via official contact channels before taking any action.');
    actions.push('Inspect the true sender address or domain name carefully for subtle spelling discrepancies.');
    return actions;
  }

  // LOW_INCONCLUSIVE: Clear guidance to not assume safety
  actions.push('Always confirm unexpected requests (especially involving passwords, bank details, or emergency funds) via a trusted out-of-band channel.');
  actions.push('Check the full sender address and web domain independently.');
  actions.push('If unsure, do not enter sensitive credentials on unknown pages.');

  return actions;
}

