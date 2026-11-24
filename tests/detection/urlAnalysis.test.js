import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeUrl } from '../../src/detection/index.js';
import { RISK_LEVELS } from '../../src/detection/types.js';

test('URL Analysis - Raw IP address hostname is flagged as Critical', () => {
  const input = 'http://192.168.1.105/login/verify-account';
  const result = analyzeUrl(input);

  assert.ok(result.riskScore >= 40, `Expected high/critical score, got ${result.riskScore}`);
  assert.ok(result.detectedIndicators.some(i => i.id === 'URL_IP_ADDRESS_HOST'));
  assert.ok(result.evidence.includes('192.168.1.105'));
});

test('URL Analysis - Punycode / IDN homoglyph attack is flagged as Critical', () => {
  const input = 'http://xn--pple-43d.com/login';
  const result = analyzeUrl(input);

  assert.ok(result.riskScore >= 40, `Expected high/critical score, got ${result.riskScore}`);
  assert.ok(result.detectedIndicators.some(i => i.id === 'URL_PUNYCODE_HOMOGLYPH'));
});

test('URL Analysis - Deceptive "@" HTTP Basic Auth spoofing', () => {
  const input = 'https://google.com@phishing-target.net/auth';
  const result = analyzeUrl(input);

  assert.ok(result.riskScore >= 30, `Expected high score, got ${result.riskScore}`);
  assert.ok(result.detectedIndicators.some(i => i.id === 'URL_EMBEDDED_USERINFO_DECEPTION'));
});

test('URL Analysis - Brand spoofing in subdomain with high-risk TLD', () => {
  const input = 'https://paypal.com.security-update.xyz/login';
  const result = analyzeUrl(input);

  assert.ok(result.riskScore >= 45, `Expected high risk, got ${result.riskScore}`);
  assert.ok(result.detectedIndicators.some(i => i.id === 'URL_BRAND_IMPERSONATION_SUBDOMAIN'));
  assert.ok(result.detectedIndicators.some(i => i.id === 'URL_HIGH_RISK_TLD'));
});

test('URL Analysis - Direct executable file download', () => {
  const input = 'http://cdn-update-software.net/security-patch.exe';
  const result = analyzeUrl(input);

  assert.ok(result.riskScore >= 35, `Expected high risk, got ${result.riskScore}`);
  assert.ok(result.detectedIndicators.some(i => i.id === 'URL_SUSPICIOUS_FILE_DOWNLOAD'));
  assert.ok(result.evidence.includes('.exe'));
});

test('URL Analysis - Deep subdomain nesting', () => {
  const input = 'https://a.b.c.d.secure-server.net/portal';
  const result = analyzeUrl(input);

  assert.ok(result.detectedIndicators.some(i => i.id === 'URL_DEEP_SUBDOMAIN_NESTING'));
});

test('URL Analysis - Legitimate major brand website is NOT false-positived on brand rule', () => {
  // Official paypal domain should NOT be flagged as spoofing itself!
  const input = 'https://www.paypal.com/signin';
  const result = analyzeUrl(input);

  assert.ok(!result.detectedIndicators.some(i => i.id === 'URL_BRAND_IMPERSONATION_SUBDOMAIN'));
  assert.strictEqual(result.riskScore, 0);
  assert.strictEqual(result.riskClassification.level, RISK_LEVELS.LOW_INCONCLUSIVE);
});

test('URL Analysis - Legitimate URLs (False Positive Check)', () => {
  const legitimateUrls = [
    'https://www.google.com/search?q=trapshield+cybersecurity',
    'https://github.com/facebook/react/releases',
    'https://developer.mozilla.org/en-US/docs/Web/JavaScript',
  ];

  for (const url of legitimateUrls) {
    const result = analyzeUrl(url);
    assert.strictEqual(result.riskScore, 0, `Expected 0 risk for ${url}, got ${result.riskScore}`);
    assert.strictEqual(result.riskClassification.level, RISK_LEVELS.LOW_INCONCLUSIVE);
    assert.strictEqual(result.detectedIndicators.length, 0);
  }
});

