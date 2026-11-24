import test from 'node:test';
import assert from 'node:assert/strict';
import { analyze, ANALYSIS_TYPES, RISK_LEVELS } from '../../src/detection/index.js';

test('Engine Facade - Dispatches MESSAGE analysis correctly', () => {
  const result = analyze({
    type: ANALYSIS_TYPES.MESSAGE,
    input: 'Urgent: account suspended immediately',
  });
  assert.strictEqual(result.analysisType, ANALYSIS_TYPES.MESSAGE);
  assert.ok(result.riskScore > 0);
});

test('Engine Facade - Dispatches URL analysis correctly', () => {
  const result = analyze({
    type: ANALYSIS_TYPES.URL,
    input: 'http://192.168.1.1/login',
  });
  assert.strictEqual(result.analysisType, ANALYSIS_TYPES.URL);
  assert.ok(result.riskScore > 0);
});

test('Engine Facade - Dispatches JOB_OFFER analysis correctly', () => {
  const result = analyze({
    type: ANALYSIS_TYPES.JOB_OFFER,
    input: 'Earn $5,000 weekly for 1 hour of typing. Pay registration fee to start.',
  });
  assert.strictEqual(result.analysisType, ANALYSIS_TYPES.JOB_OFFER);
  assert.ok(result.riskScore > 0);
});

test('Engine Facade - Gracefully handles empty or null input', () => {
  const result = analyze({
    type: ANALYSIS_TYPES.MESSAGE,
    input: '',
  });
  assert.strictEqual(result.riskScore, 0);
  assert.strictEqual(result.riskClassification.level, RISK_LEVELS.LOW_INCONCLUSIVE);
  assert.strictEqual(result.detectedIndicators.length, 0);
});

test('Engine Facade - Throws informative error on unsupported analysis type', () => {
  assert.throws(() => {
    analyze({
      type: 'UNKNOWN_TYPE',
      input: 'test',
    });
  }, /Unsupported analysis type/);
});

