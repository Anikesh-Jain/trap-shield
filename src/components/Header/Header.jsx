/**
 * TRAPSHIELD Header Component
 * 
 * Direction: EVIDENCE ROOM
 * Navigation bar with authentication states, role awareness, and transparency links.
 */

import React from 'react';
import { useAuth } from '../../context/AuthContext.jsx';
import './Header.css';

export function Header({ currentView, onNavigate, onOpenAuth, onOpenAccount, onOpenPrivacy }) {
  const { user, isAuthenticated, isAdmin } = useAuth();

  return (
    <header className="header-container">
      <div className="header-inner">
        <div className="header-brand" onClick={() => onNavigate('scanner')} role="button" tabIndex={0}>
          <div className="header-logo" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="m9 12 2 2 4-4" />
            </svg>
          </div>
          <div className="header-titles">
            <div className="brand-badge-row">
              <span className="header-title">TRAPSHIELD</span>
              <span className="header-badge">ENGINE V1.0</span>
            </div>
            <p className="header-subtitle">Heuristic Threat &amp; Fraud Detection Engine</p>
          </div>
        </div>

        {/* Navigation & Session Controls */}
        <div className="header-nav-actions">
          {isAuthenticated && (
            <div className="header-view-nav">
              <button
                className={`header-nav-link ${currentView === 'scanner' ? 'active' : ''}`}
                onClick={() => onNavigate('scanner')}
              >
                Scanner
              </button>
              <button
                className={`header-nav-link ${currentView === 'history' ? 'active' : ''}`}
                onClick={() => onNavigate('history')}
              >
                Archive History
              </button>
              {isAdmin && (
                <button
                  className={`header-nav-link admin-nav-pill ${currentView === 'admin' ? 'active' : ''}`}
                  onClick={() => onNavigate('admin')}
                >
                  Admin Console
                </button>
              )}
            </div>
          )}

          <button
            className="header-privacy-link"
            onClick={onOpenPrivacy}
            title="View Data Retention & Privacy Guarantees"
          >
            Privacy Policy
          </button>

          {isAuthenticated ? (
            <div className="header-user-menu">
              <button
                className="header-user-btn"
                onClick={onOpenAccount}
                title="View Examiner Account Profile"
              >
                <span className="header-user-avatar">
                  {isAdmin ? '🛡️' : '⚖️'}
                </span>
                <span className="header-user-email">
                  {user.email.split('@')[0]}
                </span>
              </button>
            </div>
          ) : (
            <div className="header-auth-buttons">
              <button
                className="header-btn-login"
                onClick={() => onOpenAuth('login')}
              >
                Sign In
              </button>
              <button
                className="header-btn-register"
                onClick={() => onOpenAuth('register')}
              >
                Create Account
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
