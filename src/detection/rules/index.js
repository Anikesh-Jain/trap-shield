/**
 * TRAPSHIELD Rule Registry
 */

import { ANALYSIS_TYPES } from '../types.js';
import { messageRules } from './messageRules.js';
import { urlRules } from './urlRules.js';
import { jobRules } from './jobRules.js';

const registry = {
  [ANALYSIS_TYPES.MESSAGE]: messageRules,
  [ANALYSIS_TYPES.URL]: urlRules,
  [ANALYSIS_TYPES.JOB_OFFER]: jobRules,
};

/**
 * Returns all rules associated with a specific analysis type
 * @param {string} analysisType 
 * @returns {Array<object>}
 */
export function getRulesForType(analysisType) {
  const rules = registry[analysisType];
  if (!rules) {
    throw new Error(`Unsupported analysis type: "${analysisType}". Expected one of: ${Object.values(ANALYSIS_TYPES).join(', ')}`);
  }
  return rules;
}

/**
 * Validates the structure and required properties of a detection rule
 * @param {object} rule 
 * @returns {boolean}
 */
export function validateRule(rule) {
  if (!rule || typeof rule !== 'object') return false;
  if (!rule.id || typeof rule.id !== 'string') return false;
  if (!rule.category || typeof rule.category !== 'string') return false;
  if (!rule.name || typeof rule.name !== 'string') return false;
  if (!rule.description || typeof rule.description !== 'string') return false;
  if (typeof rule.baseWeight !== 'number' || rule.baseWeight <= 0) return false;
  if (!rule.severity || typeof rule.severity !== 'string') return false;
  if (typeof rule.evaluate !== 'function') return false;
  return true;
}

