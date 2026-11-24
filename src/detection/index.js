/**
 * TRAPSHIELD Core Detection Engine
 * 
 * Main entry point for modular, rule-based threat and fraud analysis.
 */

import { ANALYSIS_TYPES, RISK_LEVELS, SEVERITY_LEVELS, SCORING_METADATA } from './types.js';
import { getRulesForType } from './rules/index.js';
import { parseUrlStructure } from './utils/urlParser.js';
import { normalizeText, extractUrlsFromText } from './utils/textParser.js';
import { calculateRiskScore } from './scoring/scorer.js';

export { ANALYSIS_TYPES, RISK_LEVELS, SEVERITY_LEVELS, SCORING_METADATA };

/**
 * Analyzes suspicious messages (SMS, WhatsApp, Email)
 * Extracts embedded URLs and evaluates both textual patterns and offline structural link indicators.
 * @param {string} text 
 * @returns {object} Structured detection result
 */
export function analyzeMessage(text) {
  const normalized = normalizeText(text);
  if (!normalized) {
    return calculateRiskScore([], ANALYSIS_TYPES.MESSAGE);
  }

  // Extract embedded URLs for safe, 100% offline structural inspection
  const extractedUrls = extractUrlsFromText(normalized);
  const embeddedUrlStructures = extractedUrls.map(url => ({
    raw: url,
    structure: parseUrlStructure(url),
  })).filter(u => u.structure && u.structure.isValid);

  const rules = getRulesForType(ANALYSIS_TYPES.MESSAGE);
  const context = {
    text: normalized,
    extractedUrls,
    embeddedUrlStructures,
  };
  const matches = [];

  for (const rule of rules) {
    const result = rule.evaluate(context);
    if (result && result.matched) {
      matches.push({
        rule,
        evidence: result.evidence || [],
        details: result.details || {},
      });
    }
  }

  return calculateRiskScore(matches, ANALYSIS_TYPES.MESSAGE);
}

/**
 * Analyzes suspicious URLs using pure structural/lexical inspection.
 * NEVER visits, connects to, or fetches submitted URLs.
 * @param {string} url 
 * @returns {object} Structured detection result
 */
export function analyzeUrl(url) {
  if (typeof url !== 'string' || !url.trim()) {
    return calculateRiskScore([], ANALYSIS_TYPES.URL);
  }

  const urlStructure = parseUrlStructure(url);
  const rules = getRulesForType(ANALYSIS_TYPES.URL);
  const context = { url: url.trim(), urlStructure };
  const matches = [];

  for (const rule of rules) {
    const result = rule.evaluate(context);
    if (result && result.matched) {
      matches.push({
        rule,
        evidence: result.evidence || [],
        details: result.details || {},
      });
    }
  }

  return calculateRiskScore(matches, ANALYSIS_TYPES.URL);
}

/**
 * Analyzes fraudulent job and internship offers
 * @param {string} text 
 * @returns {object} Structured detection result
 */
export function analyzeJobOffer(text) {
  const normalized = normalizeText(text);
  if (!normalized) {
    return calculateRiskScore([], ANALYSIS_TYPES.JOB_OFFER);
  }

  const rules = getRulesForType(ANALYSIS_TYPES.JOB_OFFER);
  const context = { text: normalized };
  const matches = [];

  for (const rule of rules) {
    const result = rule.evaluate(context);
    if (result && result.matched) {
      matches.push({
        rule,
        evidence: result.evidence || [],
        details: result.details || {},
      });
    }
  }

  return calculateRiskScore(matches, ANALYSIS_TYPES.JOB_OFFER);
}

/**
 * Unified dispatch analysis method
 * @param {object} params
 * @param {string} params.type - ANALYSIS_TYPES enum
 * @param {string} params.input - Text or URL string
 * @returns {object}
 */
export function analyze({ type, input }) {
  switch (type) {
    case ANALYSIS_TYPES.MESSAGE:
      return analyzeMessage(input);
    case ANALYSIS_TYPES.URL:
      return analyzeUrl(input);
    case ANALYSIS_TYPES.JOB_OFFER:
      return analyzeJobOffer(input);
    default:
      throw new Error(`Unsupported analysis type: "${type}". Expected one of: ${Object.values(ANALYSIS_TYPES).join(', ')}`);
  }
}

