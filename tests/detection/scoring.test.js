import test from 'node:test';
import assert from 'node:assert/strict';
import { calculateRiskScore } from '../../src/detection/scoring/scorer.js';
import { ANALYSIS_TYPES, RISK_LEVELS, RULE_CATEGORIES, SEVERITY_LEVELS } from '../../src/detection/types.js';

test('Scoring Engine - Clamps score strictly within [0, 100]', () => {
  // Fabricate matches with extreme weights
  const extremeMatches = [
    {
      rule: {
        id: 'R1',
        category: 'cat1',
        name: 'R1',
        description: 'D1',
        baseWeight: 50,
        severity: SEVERITY_LEVELS.CRITICAL,
      },
      evidence: ['e1'],
    },
    {
      rule: {
        id: 'R2',
        category: 'cat2',
        name: 'R2',
        description: 'D2',
        baseWeight: 50,
        severity: SEVERITY_LEVELS.CRITICAL,
      },
      evidence: ['e2'],
    },
    {
      rule: {
        id: 'R3',
        category: 'cat3',
        name: 'R3',
        description: 'D3',
        baseWeight: 50,
        severity: SEVERITY_LEVELS.CRITICAL,
      },
      evidence: ['e3'],
    },
  ];

  const result = calculateRiskScore(extremeMatches, ANALYSIS_TYPES.MESSAGE);
  assert.ok(result.riskScore <= 100, `Score must not exceed 100, was ${result.riskScore}`);
  assert.ok(result.riskScore >= 0, `Score must not be negative, was ${result.riskScore}`);
  assert.strictEqual(result.riskScore, 100);
});

test('Scoring Engine - Overlapping indicators in the same category apply diminishing returns & cap', () => {
  // 5 urgency rules matching
  const overlappingUrgencyMatches = Array.from({ length: 5 }, (_, i) => ({
    rule: {
      id: `URGENCY_${i}`,
      category: RULE_CATEGORIES.URGENCY,
      name: `Urgency Indicator ${i}`,
      description: `Urgency description ${i}`,
      baseWeight: 20,
      severity: SEVERITY_LEVELS.HIGH,
    },
    evidence: [`evidence_${i}`],
  }));

  const result = calculateUrgencyScore(overlappingUrgencyMatches);
  
  // Base weights would sum to 5 * 20 = 100.
  // With diminishing returns (20*1 + 20*0.4 + 20*0.2 + 20*0.2 + 20*0.2 = 20 + 8 + 4 + 4 + 4 = 40)
  // Category total must not double count linearly to 100!
  assert.ok(result.riskScore <= 45, `Category total must respect diminishing returns / cap, was ${result.riskScore}`);
  assert.ok(result.riskScore > 20, 'Should be higher than single match');
});

function calculateUrgencyScore(matches) {
  return calculateRiskScore(matches, ANALYSIS_TYPES.MESSAGE);
}

test('Scoring Engine - Non-probability disclaimer is present in metadata', () => {
  const result = calculateRiskScore([], ANALYSIS_TYPES.MESSAGE);
  assert.ok(result.scoringMetadata.interpretationNotice.includes('NOT a statistical probability of fraud'));
});

test('Scoring Engine - Score 0 is classified as LOW_INCONCLUSIVE, NEVER declared "Safe"', () => {
  const result = calculateRiskScore([], ANALYSIS_TYPES.MESSAGE);
  assert.strictEqual(result.riskScore, 0);
  assert.strictEqual(result.riskClassification.level, RISK_LEVELS.LOW_INCONCLUSIVE);
  assert.notStrictEqual(result.riskClassification.code, 'SAFE');
  assert.ok(result.riskClassification.label.includes('No Suspicious Indicators Detected'));
  assert.ok(result.riskClassification.summary.includes('does NOT certify the submission as safe'));
});

test('Scoring Engine - Explainability: Each detected indicator has an explicit applied weight', () => {
  const matches = [
    {
      rule: {
        id: 'T1',
        category: 'threat',
        name: 'Threat 1',
        description: 'Threat desc',
        baseWeight: 25,
        severity: SEVERITY_LEVELS.HIGH,
      },
      evidence: ['threat evidence'],
    },
  ];

  const result = calculateRiskScore(matches, ANALYSIS_TYPES.MESSAGE);
  assert.strictEqual(result.detectedIndicators.length, 1);
  const ind = result.detectedIndicators[0];
  assert.strictEqual(ind.baseWeight, 25);
  assert.strictEqual(ind.appliedWeight, 25);
  assert.strictEqual(result.riskScore, 25);
});

