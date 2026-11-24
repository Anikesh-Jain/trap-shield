import React, { useState } from 'react';
import './EvidenceViewer.css';

export function EvidenceViewer({ evidence = [], indicators = [] }) {
  const [copiedIndex, setCopiedIndex] = useState(null);

  if (!evidence || evidence.length === 0) {
    return null;
  }

  const handleCopy = (text, idx) => {
    navigator.clipboard?.writeText(text);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  // Find which indicator(s) triggered on a specific evidence snippet
  const getContributingIndicators = (snippet) => {
    return indicators.filter((ind) =>
      Array.isArray(ind.evidence) && ind.evidence.includes(snippet)
    );
  };

  return (
    <div className="evidence-viewer-card">
      <div className="evidence-viewer-header">
        <div className="evidence-header-left">
          <div className="evidence-header-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="4 7 4 4 20 4 20 7" />
              <line x1="9" y1="20" x2="15" y2="20" />
              <line x1="12" y1="4" x2="12" y2="20" />
            </svg>
          </div>
          <h3 className="evidence-title">Verbatim Extracted Evidence</h3>
        </div>
        <span className="evidence-count-tag">
          {evidence.length} matched fragment{evidence.length === 1 ? '' : 's'} across {indicators.length} indicator{indicators.length === 1 ? '' : 's'}
        </span>
      </div>

      <p className="evidence-subtitle">
        Verbatim substrings extracted directly from the payload that triggered the active detection rules. Multiple fragments may originate from a single rule (such as recurring urgency cues).
      </p>

      <div className="evidence-list">
        {evidence.map((item, idx) => {
          const matchedInds = getContributingIndicators(item);
          return (
            <div key={idx} className="evidence-row">
              <div className="evidence-row-content">
                <code className="evidence-code-block">{item}</code>
                {matchedInds.length > 0 && (
                  <div className="evidence-source-tags">
                    {matchedInds.map((ind) => (
                      <span key={ind.id} className="evidence-source-tag" title={ind.explanation}>
                        {ind.name}
                      </span>
                    ))}
                  </div>
                )}
              </div>
              <button
                type="button"
                className="copy-evidence-btn"
                onClick={() => handleCopy(item, idx)}
                title="Copy snippet"
              >
                {copiedIndex === idx ? (
                  <span className="copied-label">Copied</span>
                ) : (
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                  </svg>
                )}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}
