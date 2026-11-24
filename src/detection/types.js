/**
 * TRAPSHIELD Core Detection Engine - Type Definitions & Constants
 */

export const ANALYSIS_TYPES = Object.freeze({
  MESSAGE: 'MESSAGE',
  URL: 'URL',
  JOB_OFFER: 'JOB_OFFER',
});

export const SEVERITY_LEVELS = Object.freeze({
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
});

export const RISK_LEVELS = Object.freeze({
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  ELEVATED: 'ELEVATED',
  LOW_INCONCLUSIVE: 'LOW_INCONCLUSIVE',
});

export const RULE_CATEGORIES = Object.freeze({
  URGENCY: 'urgency',
  THREAT: 'threat',
  FINANCIAL_LURE: 'financial_lure',
  CREDENTIAL_HARVESTING: 'credential_harvesting',
  PAYMENT_DEMAND: 'payment_demand',
  COMMUNICATION_CHANNEL: 'communication_channel',
  IMPERSONATION: 'impersonation',
  REDIRECTION: 'redirection',
  EVASION: 'evasion',
  HOST_ANOMALY: 'host_anomaly',
  OBFUSCATION: 'obfuscation',
  STRUCTURAL_DECEPTION: 'structural_deception',
  REPUTATION: 'reputation',
  BRAND_SPOOFING: 'brand_spoofing',
  STRUCTURAL_ANOMALY: 'structural_anomaly',
  MALWARE_INDICATOR: 'malware_indicator',
  COMPENSATION_ANOMALY: 'compensation_anomaly',
  HIRING_PROCESS_ANOMALY: 'hiring_process_anomaly',
  SCAM_MODEL: 'scam_model',
  JOB_SPEC_ANOMALY: 'job_spec_anomaly',
});

export const SCORING_METADATA = Object.freeze({
  SCALE: '0–100 (Heuristic Indicator Severity)',
  DISCLAIMER: 'The risk score reflects rule-based heuristic indicator severity on a 0-100 scale, NOT a statistical probability of fraud or a guarantee of legitimacy. Submissions with zero detected indicators should be verified independently through trusted channels.',
});

