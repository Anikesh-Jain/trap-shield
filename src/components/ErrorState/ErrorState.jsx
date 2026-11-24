import React from 'react';
import './ErrorState.css';

export function ErrorState({ error, onReset }) {
  return (
    <div className="error-state-card" role="alert">
      <div className="error-icon" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="10" />
          <line x1="12" y1="8" x2="12" y2="12" />
          <line x1="12" y1="16" x2="12.01" y2="16" />
        </svg>
      </div>

      <div className="error-content">
        <h4 className="error-title">Forensic Inspection Interrupted</h4>
        <p className="error-message">
          {error?.message || 'An unexpected condition interrupted heuristic rule evaluation.'}
        </p>
      </div>

      <button type="button" className="error-reset-button" onClick={onReset}>
        Reset Scanner
      </button>
    </div>
  );
}
