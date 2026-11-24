import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeJobOffer } from '../../src/detection/index.js';
import { RISK_LEVELS } from '../../src/detection/types.js';

test('Job Analysis - Demanding upfront registration/laptop deposit', () => {
  const input = 'Congratulations! You are selected for Data Entry Specialist. Please pay a refundable security deposit of ₹2,500 to initiate laptop dispatch and registration.';
  const result = analyzeJobOffer(input);

  assert.ok(result.riskScore >= 40, `Expected critical/high score, got ${result.riskScore}`);
  assert.ok(result.detectedIndicators.some(i => i.id === 'JOB_UPFRONT_FEE_OR_SECURITY_DEPOSIT'));
  assert.ok(result.evidence.some(e => /refundable security deposit/i.test(e)));
});

test('Job Analysis - Task rating/like scam with Telegram redirection', () => {
  const input = 'Part-time opportunity: Earn $500 daily by completing simple tasks. Like YouTube videos and post hotel ratings. Contact our HR manager on Telegram @EarnFastDaily to start.';
  const result = analyzeJobOffer(input);

  assert.ok(result.riskScore >= 50, `Expected high/critical score, got ${result.riskScore}`);
  assert.ok(result.detectedIndicators.some(i => i.id === 'JOB_TASK_RATING_LIKE_SCAM'));
  assert.ok(result.detectedIndicators.some(i => i.id === 'JOB_ENCRYPTED_MESSAGING_INTERVIEW'));
});

test('Job Analysis - Major corporate brand recruitment via free Gmail address', () => {
  const input = 'Official Microsoft Careers Notice: You have been selected without an interview for Cloud Engineer role. Send your resume to microsoft.careers.recruiter@gmail.com immediately.';
  const result = analyzeJobOffer(input);

  assert.ok(result.riskScore >= 40, `Expected high score, got ${result.riskScore}`);
  assert.ok(result.detectedIndicators.some(i => i.id === 'JOB_FREE_EMAIL_RECRUITER_SPOOF'));
  assert.ok(result.detectedIndicators.some(i => i.id === 'JOB_NO_INTERVIEW_IMMEDIATE_OFFER'));
});

test('Job Analysis - Premature sensitive banking credential solicitation', () => {
  const input = 'To finalize your employment contract and salary setup, provide your bank account login and net banking password.';
  const result = analyzeJobOffer(input);

  assert.ok(result.riskScore >= 35, `Expected high score, got ${result.riskScore}`);
  assert.ok(result.detectedIndicators.some(i => i.id === 'JOB_SENSITIVE_FINANCIAL_INFO_REQUEST'));
});

test('Job Analysis - Legitimate corporate job posting (False Positive Check)', () => {
  const input = `Software Engineer (Frontend) - Acme Tech
Responsibilities:
- Build responsive React components with modern CSS.
- Collaborate with backend engineers on REST API integrations.
- Participate in peer code reviews and sprint planning.
Requirements:
- Bachelor's degree in Computer Science or equivalent experience.
- 2+ years experience with JavaScript/React.
Apply through our official careers page at careers@acme-technologies.com. Acme is an equal opportunity employer.`;

  const result = analyzeJobOffer(input);

  assert.strictEqual(result.riskScore, 0);
  assert.strictEqual(result.riskClassification.level, RISK_LEVELS.LOW_INCONCLUSIVE);
  assert.strictEqual(result.detectedIndicators.length, 0);
});

test('Job Analysis - Legitimate university internship offer with normal stipend (False Positive Check)', () => {
  const input = `Summer Research Internship - Department of Data Science
Duration: 8 weeks (June - July).
Stipend: $2,500 total for the full 8-week program.
Applicants must submit transcripts, a resume, and one faculty letter of recommendation by March 31.
Selected candidates will be invited for a 30-minute technical interview.`;

  const result = analyzeJobOffer(input);

  assert.strictEqual(result.riskScore, 0);
  assert.strictEqual(result.riskClassification.level, RISK_LEVELS.LOW_INCONCLUSIVE);
  assert.strictEqual(result.detectedIndicators.length, 0);
});

