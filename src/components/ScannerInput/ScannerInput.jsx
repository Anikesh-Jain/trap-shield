import React from 'react';
import { ANALYSIS_TYPES } from '../../detection/types.js';
import './ScannerInput.css';

const SAMPLE_PRESETS = {
  [ANALYSIS_TYPES.MESSAGE]: [
    {
      label: 'Suspicious Phishing SMS',
      type: 'threat',
      text: 'FINAL WARNING: Your Chase account has been suspended due to suspicious activity. Action required immediately within 24 hours to prevent account closure: bit.ly/reactivate-chase-now',
    },
    {
      label: 'Legitimate Bank Alert',
      type: 'clean',
      text: 'Your checking account ending in 4921 was credited with $250.00 on Nov 24, 2026. Available balance: $1,420.50. Thank you for banking with Chase.',
    },
    {
      label: 'Tax Department Coercion',
      type: 'threat',
      text: 'Notice from Income Tax Department: An arrest warrant will be issued against you unless payment is made immediately. Contact tax officer urgently.',
    },
  ],
  [ANALYSIS_TYPES.URL]: [
    {
      label: 'Brand Spoof Subdomain (XYZ)',
      type: 'threat',
      text: 'https://paypal.com.security-update.xyz/login/verify-identity',
    },
    {
      label: 'Raw IP Host with Port',
      type: 'threat',
      text: 'http://192.168.1.105:8080/secure/update-password',
    },
    {
      label: 'Legitimate Brand Domain',
      type: 'clean',
      text: 'https://www.paypal.com/signin',
    },
  ],
  [ANALYSIS_TYPES.JOB_OFFER]: [
    {
      label: 'Upfront Laptop Fee Scam',
      type: 'threat',
      text: 'Congratulations! You are selected without an interview for Data Entry Assistant. Please pay a refundable security deposit of ₹2,500 for laptop insurance before dispatch.',
    },
    {
      label: 'Telegram Video Task Scam',
      type: 'threat',
      text: 'Work from home and earn $500 daily liking YouTube videos for 1 hour a day. Contact our HR manager on Telegram @FastCashTasks to start immediately.',
    },
    {
      label: 'Legitimate Job Posting',
      type: 'clean',
      text: `Frontend Software Engineer - Acme Corp
Responsibilities: Build modern React web applications, write unit tests, and collaborate with product teams.
Requirements: 2+ years JavaScript experience. Apply via careers@acmecorp.com.`,
    },
  ],
};

const MODE_META = {
  [ANALYSIS_TYPES.MESSAGE]: {
    heading: 'Message Payload Inspection',
    description: 'Paste communication text extracted from SMS, WhatsApp, or suspicious emails.',
    placeholder: 'Paste SMS text, WhatsApp messages, or phishing email content here...',
    rows: 5,
  },
  [ANALYSIS_TYPES.URL]: {
    heading: 'Target URL Specification',
    description: 'Enter web address for structural and lexical inspection without visiting the host.',
    placeholder: 'Enter target URL (e.g., https://paypal.com.verify-user.xyz/login or http://192.168.1.50)...',
    rows: 2,
  },
  [ANALYSIS_TYPES.JOB_OFFER]: {
    heading: 'Recruitment Offer & Contract Inspection',
    description: 'Paste job description, recruitment pitch, or freelance assignment details.',
    placeholder: 'Paste job offer text, recruitment WhatsApp message, or freelance assignment details here...',
    rows: 5,
  },
};

export function ScannerInput({
  mode,
  value,
  onChange,
  onAnalyze,
  onClear,
  isLoading,
  validationError,
}) {
  const samples = SAMPLE_PRESETS[mode] || [];
  const meta = MODE_META[mode] || MODE_META[ANALYSIS_TYPES.MESSAGE];

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      onAnalyze();
    }
  };

  return (
    <div className="scanner-input-card">
      <div className="scanner-card-header">
        <div>
          <h2 className="scanner-card-title">{meta.heading}</h2>
          <p className="scanner-card-desc">{meta.description}</p>
        </div>
      </div>

      {mode === ANALYSIS_TYPES.URL && (
        <div className="offline-safety-banner" role="status">
          <div className="safety-banner-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="m9 12 2 2 4-4" />
            </svg>
          </div>
          <div className="safety-banner-text">
            <strong>Offline Forensic Isolation:</strong> TRAPSHIELD operates strictly offline. Submitted URLs are inspected structurally and are <em>never visited or queried</em> over the network.
          </div>
        </div>
      )}

      {/* Preset Reference Chips */}
      <div className="sample-presets-row">
        <span className="sample-presets-label">Exemplar Presets:</span>
        <div className="sample-chips">
          {samples.map((sample, idx) => (
            <button
              key={idx}
              type="button"
              className={`sample-chip ${sample.type === 'clean' ? 'sample-clean' : 'sample-threat'}`}
              onClick={() => onChange(sample.text)}
              disabled={isLoading}
            >
              <span className="chip-dot" aria-hidden="true" />
              <span>{sample.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Input Field Area */}
      <div className={`input-field-wrapper ${validationError ? 'has-error' : ''}`}>
        <textarea
          id="scanner-textarea"
          className="scanner-textarea"
          rows={meta.rows}
          placeholder={meta.placeholder}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={isLoading}
          aria-label="Content to analyze"
          aria-invalid={!!validationError}
          aria-describedby={validationError ? 'validation-error-msg' : undefined}
        />

        {validationError && (
          <div id="validation-error-msg" className="validation-error-bar" role="alert">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10" />
              <line x1="12" y1="8" x2="12" y2="12" />
              <line x1="12" y1="16" x2="12.01" y2="16" />
            </svg>
            <span>{validationError}</span>
          </div>
        )}
      </div>

      {/* Actions & Utilities Bar */}
      <div className="scanner-actions-bar">
        <div className="input-stats">
          <span className="character-count">{value.length} characters</span>
          <span className="keyboard-shortcut-hint">Ctrl + Enter to inspect</span>
        </div>

        <div className="action-buttons-group">
          {value.trim() && (
            <button
              type="button"
              className="clear-button"
              onClick={onClear}
              disabled={isLoading}
            >
              Reset Input
            </button>
          )}

          <button
            type="button"
            className="analyze-button"
            onClick={onAnalyze}
            disabled={isLoading}
          >
            {isLoading ? (
              <>
                <span className="button-spinner" aria-hidden="true" />
                <span>Evaluating Rules...</span>
              </>
            ) : (
              <>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="11" cy="11" r="8" />
                  <line x1="21" y1="21" x2="16.65" y2="16.65" />
                </svg>
                <span>Analyze Threat</span>
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
