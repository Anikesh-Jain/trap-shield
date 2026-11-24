import React from 'react';
import { ANALYSIS_TYPES } from '../../detection/types.js';
import './ModeSelector.css';

const MODES = [
  {
    id: ANALYSIS_TYPES.MESSAGE,
    title: 'Message Scanner',
    subtitle: 'SMS, WhatsApp & Phishing Email',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
        <line x1="9" y1="10" x2="15" y2="10" />
        <line x1="12" y1="7" x2="12" y2="13" />
      </svg>
    ),
  },
  {
    id: ANALYSIS_TYPES.URL,
    title: 'URL Inspector',
    subtitle: 'Structural Offline Lexical Analysis',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="10" />
        <line x1="2" y1="12" x2="22" y2="12" />
        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
      </svg>
    ),
  },
  {
    id: ANALYSIS_TYPES.JOB_OFFER,
    title: 'Job Offer Scanner',
    subtitle: 'Employment & Internship Scam Check',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="2" y="7" width="20" height="14" rx="2" ry="2" />
        <path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16" />
      </svg>
    ),
  },
];

export function ModeSelector({ activeMode, onSelectMode }) {
  return (
    <div className="mode-selector-wrapper" role="tablist" aria-label="Detection Modes">
      {MODES.map((mode) => {
        const isActive = activeMode === mode.id;
        return (
          <button
            key={mode.id}
            type="button"
            role="tab"
            aria-selected={isActive}
            className={`mode-tab-button ${isActive ? 'active' : ''}`}
            onClick={() => onSelectMode(mode.id)}
          >
            <div className="mode-tab-icon" aria-hidden="true">
              {mode.icon}
            </div>
            <div className="mode-tab-info">
              <span className="mode-tab-title">{mode.title}</span>
              <span className="mode-tab-subtitle">{mode.subtitle}</span>
            </div>
            {isActive && <span className="mode-active-indicator" aria-hidden="true" />}
          </button>
        );
      })}
    </div>
  );
}
