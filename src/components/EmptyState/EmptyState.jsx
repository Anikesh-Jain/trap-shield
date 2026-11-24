import React from 'react';
import { ANALYSIS_TYPES } from '../../detection/types.js';
import './EmptyState.css';

const MODE_CAPABILITIES = {
  [ANALYSIS_TYPES.MESSAGE]: {
    title: 'Awaiting Message Submission',
    description: 'TRAPSHIELD screens communication payloads against multi-vector phishing, extortion, and social engineering patterns.',
    checks: [
      'Artificial deadlines & coercive urgency tactics',
      'Account suspension threats & fake security alerts',
      'Law enforcement & tax authority imposter extortion',
      'OTP & banking credential harvesting attempts',
      'Unsolicited prizes, lottery claims & crypto bonuses',
      'Redirection to unmonitored Telegram/WhatsApp channels',
    ],
  },
  [ANALYSIS_TYPES.URL]: {
    title: 'Awaiting Target URL Specification',
    description: 'TRAPSHIELD inspects URL syntax, domain registration structure, and authority components purely offline.',
    checks: [
      'Raw numerical IPv4 & IPv6 hostnames',
      'Punycode (xn--) and IDN homoglyph lookalike characters',
      'Embedded userinfo deception (@ authority spoofing)',
      'Brand impersonation in nested subdomains',
      'High-risk top-level domains (.xyz, .top, .buzz, etc.)',
      'Direct executable / script download extensions',
    ],
  },
  [ANALYSIS_TYPES.JOB_OFFER]: {
    title: 'Awaiting Recruitment Pitch or Offer',
    description: 'TRAPSHIELD screens employment solicitations, internship notices, and task compensation offers for predatory recruitment patterns.',
    checks: [
      'Upfront registration, training, or laptop deposit demands',
      'Exorbitant compensation for low-effort / entry-level tasks',
      'Immediate unconditional hiring without interview or evaluation',
      'Task fraud schemes (video likes, hotel ratings, crypto tasks)',
      'Corporate brand impersonation using free email services (@gmail.com)',
      'Premature bank account login or net-banking credential requests',
    ],
  },
};

export function EmptyState({ mode }) {
  const info = MODE_CAPABILITIES[mode] || MODE_CAPABILITIES[ANALYSIS_TYPES.MESSAGE];

  return (
    <div className="empty-state-card">
      <div className="empty-state-badge">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="10" />
          <line x1="12" y1="16" x2="12" y2="12" />
          <line x1="12" y1="8" x2="12.01" y2="8" />
        </svg>
        <span>STANDBY INSPECTION MODE</span>
      </div>

      <h3 className="empty-state-title">{info.title}</h3>
      <p className="empty-state-desc">{info.description}</p>

      <div className="capabilities-grid">
        <span className="capabilities-label">Active Forensic Rule Checks:</span>
        <ul className="capabilities-list">
          {info.checks.map((check, idx) => (
            <li key={idx} className="capability-item">
              <span className="check-bullet" aria-hidden="true">✓</span>
              <span>{check}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
