/**
 * TRAPSHIELD Administrative Console
 * 
 * Direction: EVIDENCE ROOM
 * STRICT SERVER-SIDE AUTHORIZATION:
 * Admin operations require role: 'admin' and are recorded in the immutable audit log.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { api } from '../../api/client.js';
import './AdminDashboard.css';

export function AdminDashboard({ onClose, onOpenScanReport }) {
  const [activeTab, setActiveTab] = useState('stats'); // 'stats' | 'users' | 'userScans' | 'audit'
  const [stats, setStats] = useState(null);
  const [users, setUsers] = useState([]);
  const [usersPagination, setUsersPagination] = useState({ page: 1, limit: 20, total: 0, totalPages: 1 });
  const [selectedUser, setSelectedUser] = useState(null);
  const [selectedUserScans, setSelectedUserScans] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [actionMessage, setActionMessage] = useState('');

  // 1. Fetch Platform Stats
  const loadStats = useCallback(async () => {
    setIsLoading(true);
    setError('');
    try {
      const res = await api.admin.getStats();
      setStats(res.data);
    } catch (err) {
      setError(err.message || 'Failed to load platform statistics.');
    } finally {
      setIsLoading(false);
    }
  }, []);

  // 2. Fetch Users List
  const loadUsers = useCallback(async (page = 1) => {
    setIsLoading(true);
    setError('');
    try {
      const res = await api.admin.getUsers({ page, limit: 20 });
      setUsers(res.data.users || []);
      setUsersPagination(res.data.pagination || { page, limit: 20, total: 0, totalPages: 1 });
    } catch (err) {
      setError(err.message || 'Failed to retrieve registered users.');
    } finally {
      setIsLoading(false);
    }
  }, []);

  // 3. Fetch User Scans
  const loadUserScans = async (user) => {
    setIsLoading(true);
    setError('');
    setSelectedUser(user);
    try {
      const res = await api.admin.getUserScans(user.id);
      setSelectedUserScans(res.data.scans || []);
      setActiveTab('userScans');
    } catch (err) {
      setError(err.message || 'Failed to retrieve scans for this user.');
    } finally {
      setIsLoading(false);
    }
  };

  // 4. Toggle User Status (Suspend/Reactivate)
  const handleToggleUserStatus = async (user) => {
    const nextStatus = !user.isActive;
    const promptMessage = nextStatus
      ? `Reactivate account for ${user.email}?`
      : `Suspend account for ${user.email}? This will immediately invalidate active sessions.`;

    if (!window.confirm(promptMessage)) return;

    try {
      await api.admin.updateUserStatus(user.id, nextStatus);
      setUsers((prev) =>
        prev.map((u) => (u.id === user.id ? { ...u, isActive: nextStatus } : u))
      );
      setActionMessage(`Account for ${user.email} was successfully ${nextStatus ? 'reactivated' : 'suspended'}.`);
      setTimeout(() => setActionMessage(''), 4000);
    } catch (err) {
      setError(err.message || 'Failed to update user status.');
    }
  };

  // 5. Fetch Audit Logs
  const loadAuditLogs = useCallback(async () => {
    setIsLoading(true);
    setError('');
    try {
      const res = await api.admin.getAuditLogs();
      setAuditLogs(res.data.logs || []);
    } catch (err) {
      setError(err.message || 'Failed to load administrative audit trail.');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab === 'stats') loadStats();
    if (activeTab === 'users') loadUsers(1);
    if (activeTab === 'audit') loadAuditLogs();
  }, [activeTab, loadStats, loadUsers, loadAuditLogs]);

  return (
    <div className="admin-console-card">
      <div className="admin-console-header">
        <div>
          <div className="admin-seal-title-row">
            <span className="admin-badge-seal">ADMINISTRATIVE CONSOLE</span>
            <span className="admin-role-indicator">Server-Side Authorized</span>
          </div>
          <h2 className="admin-console-title">TRAPSHIELD Forensic Oversight</h2>
          <p className="admin-console-subtitle">
            Platform governance, registered user management, and evidence audit trails.
          </p>
        </div>
        <button className="admin-btn-back" onClick={onClose}>
          ← Return to Scanner
        </button>
      </div>

      {/* Admin Navigation Tabs */}
      <div className="admin-nav-tabs">
        <button
          className={`admin-nav-tab ${activeTab === 'stats' ? 'active' : ''}`}
          onClick={() => setActiveTab('stats')}
        >
          📊 Platform Statistics
        </button>
        <button
          className={`admin-nav-tab ${activeTab === 'users' ? 'active' : ''}`}
          onClick={() => setActiveTab('users')}
        >
          👥 Registered Examiners ({stats?.users?.total ?? '…'})
        </button>
        {selectedUser && (
          <button
            className={`admin-nav-tab ${activeTab === 'userScans' ? 'active' : ''}`}
            onClick={() => setActiveTab('userScans')}
          >
            🔍 Scans for {selectedUser.email.split('@')[0]}
          </button>
        )}
        <button
          className={`admin-nav-tab ${activeTab === 'audit' ? 'active' : ''}`}
          onClick={() => setActiveTab('audit')}
        >
          📜 Audit Trail
        </button>
      </div>

      {actionMessage && (
        <div className="admin-success-banner" role="status">
          <span>✓ {actionMessage}</span>
        </div>
      )}

      {error && (
        <div className="admin-error-banner" role="alert">
          <span>⚠ {error}</span>
        </div>
      )}

      {/* TAB 1: Platform Stats */}
      {activeTab === 'stats' && (
        <div className="admin-tab-content">
          {isLoading && !stats ? (
            <div className="admin-loading-spinner">Loading platform metrics…</div>
          ) : stats ? (
            <>
              <div className="stats-metric-grid">
                <div className="stat-card">
                  <span className="stat-card-label">Total Users</span>
                  <span className="stat-card-value">{stats.users.total}</span>
                  <span className="stat-card-sub">
                    {stats.users.active} Active • {stats.users.suspended} Suspended
                  </span>
                </div>

                <div className="stat-card">
                  <span className="stat-card-label">Saved Registered Scans</span>
                  <span className="stat-card-value">{stats.scans.totalSavedRegisteredScans}</span>
                  <span className="stat-card-sub">90-Day Auto-Purge Protected</span>
                </div>

                <div className="stat-card">
                  <span className="stat-card-label">Guest Scans Recorded</span>
                  <span className="stat-card-value">{stats.scans.totalGuestScansLogged}</span>
                  <span className="stat-card-sub">Zero-Retention (Metadata Only)</span>
                </div>
              </div>

              <div className="stats-risk-distribution-card">
                <h3 className="section-card-title">Threat Classification Spectrum</h3>
                <div className="risk-spectrum-row">
                  <div className="risk-spectrum-bar-item critical">
                    <span className="risk-spectrum-count">{stats.scans.riskDistribution.CRITICAL || 0}</span>
                    <span className="risk-spectrum-label">Critical</span>
                  </div>
                  <div className="risk-spectrum-bar-item high">
                    <span className="risk-spectrum-count">{stats.scans.riskDistribution.HIGH || 0}</span>
                    <span className="risk-spectrum-label">High</span>
                  </div>
                  <div className="risk-spectrum-bar-item elevated">
                    <span className="risk-spectrum-count">
                      {(stats.scans.riskDistribution.ELEVATED || 0) + (stats.scans.riskDistribution.MEDIUM || 0)}
                    </span>
                    <span className="risk-spectrum-label">Elevated</span>
                  </div>
                  <div className="risk-spectrum-bar-item low">
                    <span className="risk-spectrum-count">
                      {(stats.scans.riskDistribution.LOW_INCONCLUSIVE || 0) + (stats.scans.riskDistribution.LOW || 0)}
                    </span>
                    <span className="risk-spectrum-label">Low / Inconclusive</span>
                  </div>
                </div>
              </div>
            </>
          ) : null}
        </div>
      )}

      {/* TAB 2: Registered Users Management */}
      {activeTab === 'users' && (
        <div className="admin-tab-content">
          <div className="users-table-wrapper">
            <table className="admin-table">
              <thead>
                <tr>
                  <th>Examiner Email</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th>Preserved Scans</th>
                  <th>Registered</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id} className={!u.isActive ? 'row-suspended' : ''}>
                    <td className="table-email-cell">
                      <strong>{u.email}</strong>
                    </td>
                    <td>
                      <span className={`table-role-tag ${u.role === 'admin' ? 'tag-admin' : 'tag-user'}`}>
                        {u.role}
                      </span>
                    </td>
                    <td>
                      <span className={`table-status-tag ${u.isActive ? 'status-active' : 'status-suspended'}`}>
                        {u.isActive ? 'Active' : 'Suspended'}
                      </span>
                    </td>
                    <td>
                      <span className="table-scan-count">{u.totalScans}</span>
                    </td>
                    <td className="table-date-cell">
                      {new Date(u.createdAt).toLocaleDateString()}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <div className="table-actions-group">
                        <button
                          className="table-btn-inspect"
                          onClick={() => loadUserScans(u)}
                          title="View this user's saved scans"
                        >
                          Scans ({u.totalScans})
                        </button>
                        {u.role !== 'admin' && (
                          <button
                            className={`table-btn-status ${u.isActive ? 'btn-suspend' : 'btn-activate'}`}
                            onClick={() => handleToggleUserStatus(u)}
                          >
                            {u.isActive ? 'Suspend' : 'Reactivate'}
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {usersPagination.totalPages > 1 && (
            <div className="admin-pagination">
              <button
                className="pagination-btn"
                disabled={usersPagination.page <= 1}
                onClick={() => loadUsers(usersPagination.page - 1)}
              >
                ← Prev
              </button>
              <span>Page {usersPagination.page} of {usersPagination.totalPages}</span>
              <button
                className="pagination-btn"
                disabled={usersPagination.page >= usersPagination.totalPages}
                onClick={() => loadUsers(usersPagination.page + 1)}
              >
                Next →
              </button>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: Selected User Scans Viewer */}
      {activeTab === 'userScans' && selectedUser && (
        <div className="admin-tab-content">
          <div className="user-scans-header">
            <div>
              <h3 className="section-card-title">Saved Scans for {selectedUser.email}</h3>
              <p className="admin-console-subtitle">
                Authorized administrative inspection of preserved forensic evidence (Audited).
              </p>
            </div>
            <button className="admin-btn-back" onClick={() => setActiveTab('users')}>
              ← Back to Users
            </button>
          </div>

          {selectedUserScans.length === 0 ? (
            <div className="admin-empty-notice">
              <p>This user has no saved scans in their 90-day archive.</p>
            </div>
          ) : (
            <div className="user-scans-list">
              {selectedUserScans.map((s) => (
                <div key={s.id} className="user-scan-card">
                  <div className="user-scan-card-top">
                    <span className="history-type-tag">{s.analysisType}</span>
                    <span className="user-scan-date">{new Date(s.createdAt).toLocaleString()}</span>
                    <div className="user-scan-score-badge">
                      <span>Score: <strong>{s.riskScore}</strong></span>
                      <span className={`history-risk-badge risk-badge-${(s.riskClassification?.level || 'low').toLowerCase()}`}>
                        {s.riskClassification?.level || 'LOW'}
                      </span>
                    </div>
                  </div>

                  <div className="user-scan-payload-box">
                    <span className="payload-box-label">Submitted Content:</span>
                    <pre className="payload-box-code">{s.submittedContent}</pre>
                  </div>

                  <div className="user-scan-indicators">
                    <span className="payload-box-label">
                      Detected Signatures ({s.detectedIndicators?.length || 0}):
                    </span>
                    <div className="indicator-tags-row">
                      {s.detectedIndicators?.map((ind, i) => (
                        <span key={i} className="indicator-tag-pill">
                          {ind.title || ind.id}
                        </span>
                      ))}
                    </div>
                  </div>

                  {onOpenScanReport && (
                    <button
                      className="user-scan-open-report-btn"
                      onClick={() => onOpenScanReport(s)}
                    >
                      Open in Full Forensic Evidence Viewer →
                    </button>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 4: Audit Trail */}
      {activeTab === 'audit' && (
        <div className="admin-tab-content">
          <div className="audit-table-wrapper">
            <table className="admin-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Action</th>
                  <th>Administrator</th>
                  <th>Target User</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {auditLogs.map((log) => (
                  <tr key={log._id || log.id}>
                    <td className="table-date-cell">
                      {new Date(log.createdAt).toLocaleString()}
                    </td>
                    <td>
                      <span className="audit-action-tag">{log.action}</span>
                    </td>
                    <td>{log.adminEmail}</td>
                    <td>{log.targetUserEmail || '—'}</td>
                    <td className="audit-details-cell">
                      {log.details ? JSON.stringify(log.details) : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

