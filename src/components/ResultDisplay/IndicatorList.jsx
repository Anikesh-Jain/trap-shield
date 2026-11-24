import React from 'react';
import './IndicatorList.css';

export function IndicatorList({ indicators = [] }) {
  if (indicators.length === 0) {
    return (
      <div className="indicators-empty-panel">
        <div className="indicators-empty-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
            <polyline points="22 4 12 14.01 9 11.01" />
          </svg>
        </div>
        <div className="indicators-empty-content">
          <h4 className="empty-panel-title">No Suspicious Threat Indicators Detected</h4>
          <p className="empty-panel-desc">
            The submitted content did not trigger any active heuristic scam, phishing, or coercion rules in the detection registry.
          </p>
          <div className="unverified-advisory">
            <strong>Forensic Advisory:</strong> Clean scans indicate an absence of known signatures in our current catalog, NOT proof of authenticity. Novel threats and targeted social engineering may not trigger automated rules. Always verify unusual requests independently through trusted channels.
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="indicators-container">
      <div className="indicators-header">
        <h3 className="section-title">
          Detected Threat Indicators
          <span className="indicator-count-badge">{indicators.length}</span>
        </h3>
        <span className="indicators-scoring-note">
          Category-grouped diminishing returns model applied
        </span>
      </div>

      <div className="indicator-cards-stack">
        {indicators.map((indicator, idx) => (
          <div key={indicator.id || idx} className={`indicator-card severity-${indicator.severity?.toLowerCase()}`}>
            <div className="indicator-card-top">
              <div className="indicator-badges">
                <span className={`severity-badge sev-${indicator.severity?.toLowerCase()}`}>
                  {indicator.severity}
                </span>
                <span className="category-pill">{indicator.category}</span>
              </div>
              <div className="weight-badge" title={`Base weight: ${indicator.baseWeight} pts`}>
                +{indicator.appliedWeight} pts
              </div>
            </div>

            <h4 className="indicator-name">{indicator.name}</h4>
            <p className="indicator-explanation">{indicator.explanation}</p>

            {indicator.evidence && indicator.evidence.length > 0 && (
              <div className="indicator-evidence-section">
                <span className="evidence-inline-label">Matched Fragment:</span>
                <div className="evidence-chips-wrap">
                  {indicator.evidence.map((snippet, sIdx) => (
                    <code key={sIdx} className="evidence-snippet-chip">
                      "{snippet}"
                    </code>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
