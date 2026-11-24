/**
 * TRAPSHIELD Weighted Scoring Engine
 * 
 * DESIGN PRINCIPLES:
 * 1. Explainability: Every point in the final score is attributable to an indicator's applied weight.
 * 2. Overlap Protection: Category-based grouping with diminishing returns prevents inflating scores
 *    when multiple overlapping cues in the same category are triggered.
 * 3. Bounded Scale (0-100): Clamped rigorously between 0 and 100.
 * 4. Non-Probabilistic: Expressed strictly as heuristic severity, never as a "probability of fraud".
 */

import { SCORING_METADATA } from '../types.js';
import { classifyRisk, generateRecommendedActions } from './classifications.js';

const CATEGORY_CAP = 45; // Maximum score contribution from a single category
const RANK_MULTIPLIERS = [1.0, 0.4, 0.2];

/**
 * Calculates weighted score from evaluated matches, applying overlap protection
 * @param {Array<{ rule: object, evidence: string[], details?: object }>} evaluatedMatches 
 * @param {string} analysisType 
 * @returns {object} Structured analysis result
 */
export function calculateRiskScore(evaluatedMatches, analysisType) {
  // If no matches, return baseline result with explicit unverified status
  if (!evaluatedMatches || evaluatedMatches.length === 0) {
    const classification = classifyRisk(0);
    return {
      analysisType,
      riskScore: 0,
      riskClassification: classification,
      scoringMetadata: {
        scale: SCORING_METADATA.SCALE,
        interpretationNotice: SCORING_METADATA.DISCLAIMER,
        categoryBreakdown: {},
      },
      detectedIndicators: [],
      evidence: [],
      explanations: [],
      recommendedActions: generateRecommendedActions({
        level: classification.level,
        detectedIndicators: [],
        analysisType,
      }),
      timestamp: new Date().toISOString(),
    };
  }

  // 1. Group matches by category
  const categoryGroups = new Map();
  for (const match of evaluatedMatches) {
    const cat = match.rule.category;
    if (!categoryGroups.has(cat)) {
      categoryGroups.set(cat, []);
    }
    categoryGroups.get(cat).push(match);
  }

  const detectedIndicators = [];
  const categoryBreakdown = {};
  let totalRawScore = 0;

  // 2. Process each category with diminishing returns and category cap
  for (const [category, matches] of categoryGroups.entries()) {
    // Sort descending by baseWeight so highest impact indicator gets full weight
    matches.sort((a, b) => b.rule.baseWeight - a.rule.baseWeight);

    let rawCategoryTotal = 0;
    const categoryIndicators = [];

    matches.forEach((match, index) => {
      const multiplier = index < RANK_MULTIPLIERS.length 
        ? RANK_MULTIPLIERS[index] 
        : RANK_MULTIPLIERS[RANK_MULTIPLIERS.length - 1];
      
      const applied = Math.max(1, Math.round(match.rule.baseWeight * multiplier));
      rawCategoryTotal += applied;

      categoryIndicators.push({
        id: match.rule.id,
        category: match.rule.category,
        name: match.rule.name,
        severity: match.rule.severity,
        baseWeight: match.rule.baseWeight,
        appliedWeight: applied,
        evidence: match.evidence || [],
        explanation: match.rule.description,
      });
    });

    // Apply category cap if needed
    let finalCategoryTotal = rawCategoryTotal;
    if (rawCategoryTotal > CATEGORY_CAP) {
      finalCategoryTotal = CATEGORY_CAP;
      // Pro-rate applied weights so the sum matches the capped total
      const scaleFactor = CATEGORY_CAP / rawCategoryTotal;
      let runningSum = 0;

      categoryIndicators.forEach((ind, i) => {
        if (i === categoryIndicators.length - 1) {
          ind.appliedWeight = Math.max(1, CATEGORY_CAP - runningSum);
        } else {
          ind.appliedWeight = Math.max(1, Math.round(ind.appliedWeight * scaleFactor));
          runningSum += ind.appliedWeight;
        }
      });
    }

    categoryBreakdown[category] = finalCategoryTotal;
    totalRawScore += finalCategoryTotal;
    detectedIndicators.push(...categoryIndicators);
  }

  // 3. Final score bounded to [0, 100]
  const finalScore = Math.max(0, Math.min(100, Math.round(totalRawScore)));
  const classification = classifyRisk(finalScore);

  // Aggregate all unique evidence strings and explanations
  const allEvidence = [...new Set(detectedIndicators.flatMap(i => i.evidence))];
  const allExplanations = [...new Set(detectedIndicators.map(i => i.explanation))];

  return {
    analysisType,
    riskScore: finalScore,
    riskClassification: classification,
    scoringMetadata: {
      scale: SCORING_METADATA.SCALE,
      interpretationNotice: SCORING_METADATA.DISCLAIMER,
      categoryBreakdown,
    },
    detectedIndicators,
    evidence: allEvidence,
    explanations: allExplanations,
    recommendedActions: generateRecommendedActions({
      level: classification.level,
      detectedIndicators,
      analysisType,
    }),
    timestamp: new Date().toISOString(),
  };
}

