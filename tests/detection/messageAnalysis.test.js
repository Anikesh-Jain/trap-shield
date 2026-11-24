import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeMessage } from '../../src/detection/index.js';
import { RISK_LEVELS } from '../../src/detection/types.js';

test('Message Analysis - Phishing SMS with urgency and suspension threat', () => {
  const input = 'FINAL WARNING: Your Bank account has been suspended due to suspicious activity. Action required immediately within 24 hours to prevent account closure: bit.ly/reactivate-now';
  const result = analyzeMessage(input);

  assert.ok(result.riskScore >= 50, `Expected elevated/high risk, got ${result.riskScore}`);
  assert.ok(result.riskClassification.level === RISK_LEVELS.HIGH || result.riskClassification.level === RISK_LEVELS.CRITICAL);
  assert.ok(result.detectedIndicators.some(i => i.id === 'MSG_URGENT_ACTION_DEADLINE'));
  assert.ok(result.detectedIndicators.some(i => i.id === 'MSG_ACCOUNT_SUSPENSION_THREAT'));
  assert.ok(result.evidence.length > 0);
  assert.ok(result.recommendedActions.length > 0);
});

test('Message Analysis - Law enforcement coercion threat', () => {
  const input = 'This is an urgent notice from Income Tax Department. You are facing prosecution and an arrest warrant will be issued unless payment is resolved immediately.';
  const result = analyzeMessage(input);

  assert.ok(result.riskScore >= 40, `Expected high risk, got ${result.riskScore}`);
  assert.ok(result.detectedIndicators.some(i => i.id === 'MSG_LEGAL_LAW_ENFORCEMENT_THREAT'));
  assert.ok(result.evidence.some(e => /arrest warrant|law enforcement|prosecution/i.test(e)));
});

test('Message Analysis - OTP solicitation scam', () => {
  const input = 'Your card verification failed. Support agent needs to verify. Reply with your OTP and PIN immediately to unlock your debit card.';
  const result = analyzeMessage(input);

  assert.ok(result.riskScore >= 40, `Expected high score, got ${result.riskScore}`);
  assert.ok(result.detectedIndicators.some(i => i.id === 'MSG_CREDENTIAL_OTP_SOLICITATION'));
});

test('Message Analysis - Lottery / Prize lure', () => {
  const input = 'Congratulations you won an exclusive cash prize of $50,000 in our international lottery! Claim your prize now.';
  const result = analyzeMessage(input);

  assert.ok(result.riskScore >= 25, `Expected high lure score, got ${result.riskScore}`);
  assert.ok(result.detectedIndicators.some(i => i.id === 'MSG_FINANCIAL_LURE_PRIZE'));
});

test('Message Analysis - Delivery imposter text', () => {
  const input = 'USPS: Your package cannot be delivered due to incomplete address information. Pay shipping fee to update your address to receive package.';
  const result = analyzeMessage(input);

  assert.ok(result.riskScore >= 20, `Expected elevated score, got ${result.riskScore}`);
  assert.ok(result.detectedIndicators.some(i => i.id === 'MSG_DELIVERY_IMPOSTER'));
});

test('Message Analysis - Legitimate bank transaction notification (False Positive Check)', () => {
  const input = 'Your checking account ending in 4921 was credited with $250.00 on Nov 24, 2026. Available balance: $1,420.50. Thank you for banking with Chase.';
  const result = analyzeMessage(input);

  assert.strictEqual(result.riskScore, 0);
  assert.strictEqual(result.riskClassification.level, RISK_LEVELS.LOW_INCONCLUSIVE);
  // Ensure we DO NOT label it "Safe"
  assert.notStrictEqual(result.riskClassification.code, 'SAFE');
  assert.strictEqual(result.detectedIndicators.length, 0);
});

test('Message Analysis - Legitimate team meeting deadline (False Positive Check)', () => {
  const input = 'Hey team, please review the presentation slides before our 3 PM meeting today. Let me know if you have any feedback.';
  const result = analyzeMessage(input);

  assert.strictEqual(result.riskScore, 0);
  assert.strictEqual(result.riskClassification.level, RISK_LEVELS.LOW_INCONCLUSIVE);
});

test('Message Analysis - Legitimate e-commerce shipment confirmation (False Positive Check)', () => {
  const input = 'Your order #98234 has been shipped via BlueDart. Track delivery progress using standard tracking portal. Expected delivery by Friday.';
  const result = analyzeMessage(input);

  assert.strictEqual(result.riskScore, 0);
  assert.strictEqual(result.riskClassification.level, RISK_LEVELS.LOW_INCONCLUSIVE);
});

// ============================================================================
// REGRESSION TESTS FOR IMPROVED DETECTION COVERAGE & EMBEDDED URL INSPECTION
// ============================================================================

test('Regression 1: WhatsApp redirection in a phishing message', () => {
  const input = 'Your account KYC is pending. Contact our verification officer on WhatsApp if you need assistance to avoid account lock.';
  const result = analyzeMessage(input);

  assert.ok(result.detectedIndicators.some(i => i.id === 'MSG_UNOFFICIAL_MESSAGING_REDIRECT'), 'Should detect WhatsApp redirect');
  assert.ok(result.evidence.some(e => /whatsapp/i.test(e)), 'Evidence should include WhatsApp redirect fragment');
});

test('Regression 2: Telegram redirection in a suspicious message', () => {
  const input = 'Urgent update regarding your card: join our Telegram group t.me/secure_support_desk to unfreeze your access immediately.';
  const result = analyzeMessage(input);

  assert.ok(result.detectedIndicators.some(i => i.id === 'MSG_UNOFFICIAL_MESSAGING_REDIRECT'), 'Should detect Telegram redirect');
  assert.ok(result.evidence.some(e => /t\.me\/secure_support_desk|telegram/i.test(e)), 'Evidence should capture telegram reference');
});

test('Regression 3: Message containing an embedded suspicious-looking URL (Raw IP host)', () => {
  const input = 'Action required: Login to your portal at http://192.168.1.100/login/update to review security changes.';
  const result = analyzeMessage(input);

  assert.ok(result.detectedIndicators.some(i => i.id === 'MSG_EMBEDDED_SUSPICIOUS_URL'), 'Should detect embedded raw IP URL');
  assert.ok(result.evidence.some(e => e.includes('192.168.1.100')), 'Evidence should include IP URL');
});

test('Regression 4: Legitimate message mentioning WhatsApp without suspicious context (False Positive Check)', () => {
  const input = 'Hey Sarah, I sent the family vacation photos on WhatsApp. Let me know when you get a chance to see them!';
  const result = analyzeMessage(input);

  assert.strictEqual(result.riskScore, 0, 'Casual WhatsApp mention must not trigger risk');
  assert.strictEqual(result.riskClassification.level, RISK_LEVELS.LOW_INCONCLUSIVE);
  assert.strictEqual(result.detectedIndicators.length, 0);
});

test('Regression 5: Legitimate bank notification without coercive language (False Positive Check)', () => {
  const input = 'Dear customer, your SBI account XX4321 was credited with INR 5,000 on 24-Nov-2026. Available balance: INR 24,500. Download Yono SBI app or visit https://www.onlinesbi.sbi for details.';
  const result = analyzeMessage(input);

  assert.strictEqual(result.riskScore, 0, 'Official bank credit notice with authentic domain must be 0 risk');
  assert.strictEqual(result.riskClassification.level, RISK_LEVELS.LOW_INCONCLUSIVE);
  assert.strictEqual(result.detectedIndicators.length, 0);
});

test('Regression 6: Message containing a legitimate URL (False Positive Check)', () => {
  const input = 'Hi team, please review the official documentation at https://react.dev/learn before tomorrow afternoon.';
  const result = analyzeMessage(input);

  assert.strictEqual(result.riskScore, 0, 'Message with legitimate HTTPS URL must have 0 risk');
  assert.strictEqual(result.riskClassification.level, RISK_LEVELS.LOW_INCONCLUSIVE);
  assert.strictEqual(result.detectedIndicators.length, 0);
});

test('Regression 7: Message containing multiple independent indicators without duplicate evidence', () => {
  const input = 'URGENT: Your account will be blocked immediately. Verify at http://192.168.1.50/login. Contact support on WhatsApp.';
  const result = analyzeMessage(input);

  assert.ok(result.detectedIndicators.length >= 3, 'Should match urgency, threat, redirect, and embedded URL');
  
  // Verify evidence deduplication: all items in result.evidence must be unique
  const uniqueCount = new Set(result.evidence).size;
  assert.strictEqual(uniqueCount, result.evidence.length, 'Evidence array must contain zero duplicate strings');
});

test('Regression 8: User test case - SBI KYC Phishing SMS detects all attack vectors', () => {
  const input = `URGENT: Your SBI bank account will be blocked today due to incomplete KYC verification. You must update your KYC immediately to avoid suspension.

Click here to verify your account: http://sbi-kyc-verification.example.com

If you fail to complete verification within 2 hours, your account access will be permanently suspended.

Do not ignore this message. Contact our verification officer on WhatsApp if you need assistance.`;

  const result = analyzeMessage(input);

  // Must detect urgency
  assert.ok(result.detectedIndicators.some(i => i.id === 'MSG_URGENT_ACTION_DEADLINE'), 'Must detect urgency deadline');
  // Must detect account suspension threat
  assert.ok(result.detectedIndicators.some(i => i.id === 'MSG_ACCOUNT_SUSPENSION_THREAT'), 'Must detect suspension threat');
  // Must detect WhatsApp redirection
  assert.ok(result.detectedIndicators.some(i => i.id === 'MSG_UNOFFICIAL_MESSAGING_REDIRECT'), 'Must detect WhatsApp redirection');
  // Must detect brand impersonation in embedded link
  assert.ok(result.detectedIndicators.some(i => i.id === 'MSG_EMBEDDED_BRAND_SPOOF_URL'), 'Must detect brand impersonation in embedded link');
  // Must detect insecure HTTP verification link
  assert.ok(result.detectedIndicators.some(i => i.id === 'MSG_INSECURE_HTTP_VERIFICATION_LINK'), 'Must detect insecure HTTP link');

  // Total detected indicators must be at least 4 (previously was only 2)
  assert.ok(result.detectedIndicators.length >= 4, `Expected at least 4 indicators, got ${result.detectedIndicators.length}`);

  // Risk classification must be CRITICAL or HIGH
  assert.ok(result.riskClassification.level === RISK_LEVELS.CRITICAL, `Expected CRITICAL risk for multi-vector phishing, got ${result.riskClassification.level}`);
  assert.ok(result.riskScore >= 71, `Expected riskScore >= 71, got ${result.riskScore}`);

  // Evidence array must be deduplicated
  assert.strictEqual(new Set(result.evidence).size, result.evidence.length);
});
