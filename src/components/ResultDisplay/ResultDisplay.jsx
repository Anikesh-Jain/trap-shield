import React from 'react';
import { ScoreMeter } from './ScoreMeter.jsx';
import { IndicatorList } from './IndicatorList.jsx';
import { EvidenceViewer } from './EvidenceViewer.jsx';
import { RecommendedActions } from './RecommendedActions.jsx';
import './ResultDisplay.css';

export function ResultDisplay({ result }) {
  if (!result) return null;

  const {
    riskScore,
    riskClassification,
    scoringMetadata,
    detectedIndicators,
    evidence,
    recommendedActions,
    analysisType,
    timestamp,
  } = result;

  const categoryBreakdown = scoringMetadata?.categoryBreakdown || {};
  const breakdownEntries = Object.entries(categoryBreakdown);

  return (
    <div className="result-display-wrapper" role="region" aria-label="Analysis Results">
      {/* 1. Score Meter & High-Level Classification */}
      <ScoreMeter
        score={riskScore}
        classification={riskClassification}
        metadata={scoringMetadata}
      />

      {/* Category Breakdown Pill Strip (when indicators detected) */}
      {breakdownEntries.length > 0 && (
        <div className="breakdown-strip">
          <span className="breakdown-label">Category Attribution:</span>
          <div className="breakdown-pills">
            {breakdownEntries.map(([category, points]) => (
              <span key={category} className="breakdown-pill">
                <span className="cat-name">{category}</span>
                <span className="cat-points">+{points} pts</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {/* 2. Detected Indicators */}
      <IndicatorList indicators={detectedIndicators} />

      {/* 3. Highlighted Evidence Snippets */}
      <EvidenceViewer evidence={evidence} indicators={detectedIndicators} />

      {/* 4. Actionable Defensive Protocols */}
      <RecommendedActions
        actions={recommendedActions}
        riskLevel={riskClassification?.level}
      />

      {/* Analysis Meta Footer */}
      <div className="result-footer-meta">
        <span>Analysis Modality: <strong>{analysisType}</strong></span>
        <span>Inspection Timestamp: {new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span>
      </div>
    </div>
  );
}
