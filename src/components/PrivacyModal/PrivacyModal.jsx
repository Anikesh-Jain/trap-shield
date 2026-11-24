/**
 * TRAPSHIELD Transparency & Data Retention Modal
 * 
 * Direction: EVIDENCE ROOM
 */

import React, { useState, useEffect } from 'react';
import { api } from '../../api/client.js';
import './PrivacyModal.css';

export function PrivacyModal({ isOpen, onClose }) {
  const [policy, setPolicy] = useState(null);

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && isOpen) onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  useEffect(() => {
    if (isOpen) {
      api.privacy.getPolicy()
        .then((res) => setPolicy(res.data))
        .catch(() => {
          // Reliable fallback
          setPolicy({
            version: '1.0.0',
            effectiveDate: '2026-11-24',
            guarantees: [
              {
                scope: 'GUEST_SCANS',
                policy: 'Zero Data Retention Policy',
                disclosure: 'Unauthenticated guest scans do not require an account. Submitted message texts, URLs, and job descriptions are NEVER stored in the database or persistent log files.',
              },
              {
                scope: 'REGISTERED_USER_SCANS',
                policy: '90-Day Automatic Expiration (TTL)',
                disclosure: 'For authenticated registered users, submitted contents and detection results are stored in their personal scan history. A MongoDB TTL index automatically purges all scan records exactly 90 days after creation.',
              },
              {
                scope: 'ADMINISTRATIVE_ACCESS_DISCLOSURE',
                policy: 'Authorized Forensic Review',
                disclosure: 'Platform administrators possess authorized server-side access to review registered users saved scan contents and analysis results for safety investigation, support, and platform abuse prevention. All viewing actions are recorded in an immutable audit log.',
              },
              {
                scope: 'OFFLINE_ANALYSIS_INTEGRITY',
                policy: 'Zero External Transmission',
                disclosure: 'TRAPSHIELD detection runs 100% offline. Submitted URLs are inspected structurally and lexically. TRAPSHIELD never visits, fetches, resolves, or transmits submitted URLs or texts to external third-party servers.',
              },
            ],
          });
        });
    }
  }, [isOpen]);

  if (!isOpen) return null;

  return (
    <div className="privacy-modal-overlay" onClick={onClose} role="dialog" aria-modal="true">
      <div className="privacy-modal-card" onClick={(e) => e.stopPropagation()}>
        <button className="privacy-modal-close" onClick={onClose} aria-label="Close dialog">
          ✕
        </button>

        <div className="privacy-modal-header">
          <div className="privacy-seal-badge" aria-hidden="true">📜</div>
          <h2 className="privacy-modal-title">Privacy &amp; Data Retention Policy</h2>
          <p className="privacy-modal-subtitle">
            Forensic disclosure on data preservation, guest anonymity, and administrative access.
          </p>
        </div>

        <div className="privacy-guarantees-list">
          {policy?.guarantees?.map((g, idx) => (
            <div key={idx} className="privacy-guarantee-card">
              <div className="guarantee-header">
                <span className="guarantee-scope-badge">{g.scope.replace(/_/g, ' ')}</span>
                <span className="guarantee-policy-title">{g.policy}</span>
              </div>
              <p className="guarantee-disclosure-text">{g.disclosure}</p>
            </div>
          ))}
        </div>

        <div className="privacy-heuristic-disclaimer">
          <span className="disclaimer-icon">⚖️</span>
          <span>
            <strong>Scoring Methodology Disclaimer:</strong> TRAPSHIELD risk scores reflect rule-based heuristic indicator severity on a 0–100 scale, NOT a statistical probability of fraud or a guarantee of legitimacy. Submissions with zero matched indicators should be verified independently.
          </span>
        </div>

        <div className="privacy-modal-footer">
          <button className="privacy-dismiss-btn" onClick={onClose}>
            Acknowledge &amp; Close
          </button>
        </div>
      </div>
    </div>
  );
}

