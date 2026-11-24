/**
 * TRAPSHIELD Account Details Modal
 * 
 * Direction: EVIDENCE ROOM
 */

import React, { useEffect } from 'react';
import { useAuth } from '../../context/AuthContext.jsx';
import './AccountModal.css';

export function AccountModal({ isOpen, onClose, onOpenAdmin }) {
  const { user, logout, isAdmin } = useAuth();

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && isOpen) onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen || !user) return null;

  const handleLogout = async () => {
    await logout();
    onClose();
  };

  return (
    <div className="account-modal-overlay" onClick={onClose} role="dialog" aria-modal="true">
      <div className="account-modal-card" onClick={(e) => e.stopPropagation()}>
        <button className="account-modal-close" onClick={onClose} aria-label="Close dialog">
          ✕
        </button>

        <div className="account-modal-header">
          <div className="account-avatar-seal" aria-hidden="true">
            {user.role === 'admin' ? '🛡️' : '⚖️'}
          </div>
          <h2 className="account-modal-title">Examiner Profile</h2>
          <p className="account-modal-subtitle">{user.email}</p>
          <span className={`account-role-pill ${user.role === 'admin' ? 'role-admin' : 'role-user'}`}>
            {user.role === 'admin' ? 'Platform Administrator' : 'Forensic Examiner'}
          </span>
        </div>

        <div className="account-details-grid">
          <div className="account-detail-item">
            <span className="account-detail-label">Account Status</span>
            <span className="account-status-active">● Active &amp; Verified</span>
          </div>

          <div className="account-detail-item">
            <span className="account-detail-label">Authentication Method</span>
            <span className="account-detail-value">Secure HTTP-Only Cookie</span>
          </div>

          <div className="account-detail-item">
            <span className="account-detail-label">Registered Since</span>
            <span className="account-detail-value">
              {user.createdAt ? new Date(user.createdAt).toLocaleDateString() : 'Active'}
            </span>
          </div>

          <div className="account-detail-item">
            <span className="account-detail-label">Last Active Session</span>
            <span className="account-detail-value">
              {user.lastLoginAt ? new Date(user.lastLoginAt).toLocaleString() : 'Current Session'}
            </span>
          </div>
        </div>

        {isAdmin && (
          <div className="account-admin-quicklaunch">
            <p className="admin-quicklaunch-text">You hold elevated administrative privileges on this platform.</p>
            <button
              className="admin-launch-btn"
              onClick={() => { onClose(); onOpenAdmin(); }}
            >
              Open Administrator Dashboard →
            </button>
          </div>
        )}

        <div className="account-modal-footer">
          <button className="account-logout-btn" onClick={handleLogout}>
            End Active Session (Logout)
          </button>
        </div>
      </div>
    </div>
  );
}

