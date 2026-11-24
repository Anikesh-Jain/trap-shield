import React from 'react';
import './RecommendedActions.css';

export function RecommendedActions({ actions = [], riskLevel }) {
  if (!actions || actions.length === 0) return null;

  return (
    <div className="recommended-actions-card">
      <div className="actions-header">
        <div className="actions-header-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
        </div>
        <div>
          <h3 className="actions-title">Recommended Safety Protocols</h3>
          <p className="actions-subtitle">Immediate defensive measures based on detected indicators</p>
        </div>
      </div>

      <ol className="actions-checklist">
        {actions.map((action, idx) => (
          <li key={idx} className="action-item">
            <span className="action-step-num" aria-hidden="true">{idx + 1}</span>
            <span className="action-text">{action}</span>
          </li>
        ))}
      </ol>
    </div>
  );
}
