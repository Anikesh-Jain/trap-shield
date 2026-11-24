/**
 * TRAPSHIELD Scan History Component
 * 
 * Direction: EVIDENCE ROOM
 * Scoped strictly to the authenticated user's saved scan history.
 * Displays 90-day retention countdown and allows individual deletion.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { api } from '../../api/client.js';
import './ScanHistory.css';

export function ScanHistory({ onOpenScan, onNewScan }) {
  const [scans, setScans] = useState([]);
  const [pagination, setPagination] = useState({ page: 1, limit: 10, total: 0, totalPages: 1 });
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [deletingId, setDeletingId] = useState(null);

  const fetchHistory = useCallback(async (page = 1) => {
    setIsLoading(true);
    setError('');
    try {
      const res = await api.scan.getHistory({ page, limit: 10 });
      setScans(res.data.scans || []);
      setPagination(res.data.pagination || { page, limit: 10, total: 0, totalPages: 1 });
    } catch (err) {
      setError(err.message || 'Failed to load scan history.');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchHistory(1);
  }, [fetchHistory]);

  const handleDelete = async (id, e) => {
    e.stopPropagation();
    if (!window.confirm('Are you sure you want to delete this scan record from your personal history?')) {
      return;
    }

    setDeletingId(id);
    try {
      await api.scan.deleteById(id);
      setScans((prev) => prev.filter((s) => s.id !== id));
      setPagination((prev) => ({ ...prev, total: Math.max(0, prev.total - 1) }));
    } catch (err) {
      alert(`Could not delete scan: ${err.message}`);
    } finally {
      setDeletingId(null);
    }
  };

  const getRiskClass = (level) => {
    switch (level) {
      case 'CRITICAL': return 'risk-badge-critical';
      case 'HIGH': return 'risk-badge-high';
      case 'ELEVATED':
      case 'MEDIUM': return 'risk-badge-medium';
      default: return 'risk-badge-low';
    }
  };

  return (
    <div className="scan-history-card">
      <div className="scan-history-header">
        <div>
          <h2 className="scan-history-title">Examiner Scan Archive</h2>
          <p className="scan-history-subtitle">
            Personal verification records saved under your authenticated session.
          </p>
        </div>
        <div className="scan-history-actions-top">
          <button className="scan-history-btn-secondary" onClick={() => fetchHistory(pagination.page)}>
            ↻ Refresh
          </button>
          <button className="scan-history-btn-primary" onClick={onNewScan}>
            + New Scan
          </button>
        </div>
      </div>

      <div className="retention-banner">
        <span className="retention-banner-icon">ℹ</span>
        <span>
          <strong>90-Day Retention Notice:</strong> Saved scan records and submitted payloads are preserved for 90 days and automatically deleted by MongoDB TTL index.
        </span>
      </div>

      {error && (
        <div className="history-error-banner" role="alert">
          <span>⚠ {error}</span>
        </div>
      )}

      {isLoading ? (
        <div className="history-loading-state">
          <div className="history-spinner" aria-hidden="true"></div>
          <p>Retrieving archival scan records…</p>
        </div>
      ) : scans.length === 0 ? (
        <div className="history-empty-state">
          <div className="history-empty-seal" aria-hidden="true">📂</div>
          <h3 className="history-empty-title">No Scan Records Found</h3>
          <p className="history-empty-text">
            You have not preserved any scans yet. Run an analysis from the scanner to automatically archive evidence.
          </p>
          <button className="scan-history-btn-primary" onClick={onNewScan}>
            Launch Scanner
          </button>
        </div>
      ) : (
        <>
          <div className="history-list">
            {scans.map((scan) => {
              const riskLevel = scan.riskClassification?.level || 'LOW';
              return (
                <div
                  key={scan.id}
                  className="history-item-row"
                  onClick={() => onOpenScan(scan)}
                  role="button"
                  tabIndex={0}
                  onKeyDown={(e) => { if (e.key === 'Enter') onOpenScan(scan); }}
                >
                  <div className="history-item-col-meta">
                    <span className="history-type-tag">{scan.analysisType}</span>
                    <span className="history-date">
                      {new Date(scan.createdAt).toLocaleDateString(undefined, {
                        year: 'numeric',
                        month: 'short',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                    </span>
                  </div>

                  <div className="history-item-col-content">
                    <p className="history-payload-preview">
                      {scan.submittedContent.length > 120
                        ? `${scan.submittedContent.substring(0, 120)}…`
                        : scan.submittedContent}
                    </p>
                    <div className="history-indicators-summary">
                      <span>{scan.detectedIndicators?.length || 0} indicator(s) detected</span>
                    </div>
                  </div>

                  <div className="history-item-col-score">
                    <div className="history-score-pill">
                      <span className="history-score-number">{scan.riskScore}</span>
                      <span className={`history-risk-badge ${getRiskClass(riskLevel)}`}>
                        {scan.riskClassification?.label ? scan.riskClassification.label.split(':')[0] : riskLevel}
                      </span>
                    </div>
                  </div>

                  <div className="history-item-col-actions">
                    <button
                      className="history-action-view"
                      onClick={(e) => { e.stopPropagation(); onOpenScan(scan); }}
                      title="Open full forensic report"
                    >
                      Inspect
                    </button>
                    <button
                      className="history-action-delete"
                      onClick={(e) => handleDelete(scan.id, e)}
                      disabled={deletingId === scan.id}
                      title="Delete record from history"
                    >
                      {deletingId === scan.id ? '…' : 'Delete'}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>

          {pagination.totalPages > 1 && (
            <div className="history-pagination">
              <button
                className="pagination-btn"
                disabled={pagination.page <= 1}
                onClick={() => fetchHistory(pagination.page - 1)}
              >
                ← Previous
              </button>
              <span className="pagination-info">
                Page {pagination.page} of {pagination.totalPages} ({pagination.total} total scans)
              </span>
              <button
                className="pagination-btn"
                disabled={pagination.page >= pagination.totalPages}
                onClick={() => fetchHistory(pagination.page + 1)}
              >
                Next →
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

