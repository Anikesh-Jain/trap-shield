import React from 'react';
import { RISK_LEVELS } from '../../detection/types.js';
import './ScoreMeter.css';

export function ScoreMeter({ score, classification, metadata }) {
  const getRiskTheme = () => {
    switch (classification?.level) {
      case RISK_LEVELS.CRITICAL:
        return {
          colorClass: 'risk-critical',
          accentColor: '#A4161A',
          label: 'CRITICAL RISK',
          icon: '⚠️',
        };
      case RISK_LEVELS.HIGH:
        return {
          colorClass: 'risk-high',
          accentColor: '#D4602A',
          label: 'HIGH RISK',
          icon: '▲',
        };
      case RISK_LEVELS.ELEVATED:
        return {
          colorClass: 'risk-elevated',
          accentColor: '#D9A21B',
          label: 'ELEVATED RISK',
          icon: '◆',
        };
      case RISK_LEVELS.LOW_INCONCLUSIVE:
      default:
        return {
          colorClass: 'risk-low',
          accentColor: '#4F8A3C',
          label: 'NO SUSPICIOUS INDICATORS DETECTED',
          icon: '✓',
        };
    }
  };

  const theme = getRiskTheme();
  const radius = 62;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className={`score-meter-card ${theme.colorClass}`}>
      <div className="gauge-section">
        <div className="circular-meter">
          <svg className="meter-svg" viewBox="0 0 160 160">
            <circle
              className="meter-bg-circle"
              cx="80"
              cy="80"
              r={radius}
              strokeWidth="11"
            />
            <circle
              className="meter-val-circle"
              cx="80"
              cy="80"
              r={radius}
              strokeWidth="11"
              stroke={theme.accentColor}
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              transform="rotate(-90 80 80)"
            />
          </svg>
          <div className="meter-center-content">
            <span className="meter-score-value">{score}</span>
            <span className="meter-score-scale">/ 100</span>
            <span className="meter-score-caption">RISK SCORE</span>
          </div>
        </div>
      </div>

      <div className="classification-section">
        <div className="classification-badge-row">
          <span className={`classification-badge ${theme.colorClass}`}>
            <span className="badge-icon" aria-hidden="true">{theme.icon}</span>
            <span>{classification?.label || theme.label}</span>
          </span>
          <span className="metric-tag">Forensic Heuristic Assessment</span>
        </div>

        <p className="classification-summary">
          {classification?.summary}
        </p>

        <div className="non-probability-disclaimer">
          <div className="disclaimer-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10" />
              <line x1="12" y1="16" x2="12" y2="12" />
              <line x1="12" y1="8" x2="12.01" y2="8" />
            </svg>
          </div>
          <span className="disclaimer-text">
            {metadata?.interpretationNotice || 'Risk score reflects rule-based heuristic indicator severity on a 0-100 scale, NOT a statistical probability of fraud. Submissions with zero detected indicators should be verified independently.'}
          </span>
        </div>
      </div>
    </div>
  );
}
