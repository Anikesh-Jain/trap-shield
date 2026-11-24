import React, { useState } from 'react';
import { Header } from './components/Header/Header.jsx';
import { ModeSelector } from './components/ModeSelector/ModeSelector.jsx';
import { ScannerInput } from './components/ScannerInput/ScannerInput.jsx';
import { ResultDisplay } from './components/ResultDisplay/ResultDisplay.jsx';
import { EmptyState } from './components/EmptyState/EmptyState.jsx';
import { ErrorState } from './components/ErrorState/ErrorState.jsx';
import { AuthModal } from './components/AuthModal/AuthModal.jsx';
import { AccountModal } from './components/AccountModal/AccountModal.jsx';
import { ScanHistory } from './components/ScanHistory/ScanHistory.jsx';
import { AdminDashboard } from './components/AdminDashboard/AdminDashboard.jsx';
import { PrivacyModal } from './components/PrivacyModal/PrivacyModal.jsx';
import { useAuth } from './context/AuthContext.jsx';
import { api } from './api/client.js';
import { analyze, ANALYSIS_TYPES } from './detection/index.js';
import './App.css';

export default function App() {
  const { user, isAuthenticated, isAdmin } = useAuth();

  // Navigation & View State
  const [currentView, setCurrentView] = useState('scanner'); // 'scanner' | 'history' | 'admin'

  // Scanner State
  const [activeMode, setActiveMode] = useState(ANALYSIS_TYPES.MESSAGE);
  const [inputMap, setInputMap] = useState({
    [ANALYSIS_TYPES.MESSAGE]: '',
    [ANALYSIS_TYPES.URL]: '',
    [ANALYSIS_TYPES.JOB_OFFER]: '',
  });
  const [resultMap, setResultMap] = useState({
    [ANALYSIS_TYPES.MESSAGE]: null,
    [ANALYSIS_TYPES.URL]: null,
    [ANALYSIS_TYPES.JOB_OFFER]: null,
  });
  const [isLoading, setIsLoading] = useState(false);
  const [validationError, setValidationError] = useState('');
  const [analysisError, setAnalysisError] = useState(null);

  // Modals State
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [authModalMode, setAuthModalMode] = useState('login');
  const [accountModalOpen, setAccountModalOpen] = useState(false);
  const [privacyModalOpen, setPrivacyModalOpen] = useState(false);

  const currentInput = inputMap[activeMode] || '';
  const currentResult = resultMap[activeMode];

  const handleSelectMode = (newMode) => {
    setActiveMode(newMode);
    setValidationError('');
    setAnalysisError(null);
  };

  const handleInputChange = (text) => {
    setInputMap((prev) => ({
      ...prev,
      [activeMode]: text,
    }));
    if (validationError) {
      setValidationError('');
    }
  };

  const handleClear = () => {
    setInputMap((prev) => ({
      ...prev,
      [activeMode]: '',
    }));
    setResultMap((prev) => ({
      ...prev,
      [activeMode]: null,
    }));
    setValidationError('');
    setAnalysisError(null);
  };

  const handleOpenAuth = (mode = 'login') => {
    setAuthModalMode(mode);
    setAuthModalOpen(true);
  };

  const handleInspectSavedScan = (scan) => {
    if (!scan) return;
    const mode = scan.analysisType;
    setActiveMode(mode);
    setInputMap((prev) => ({
      ...prev,
      [mode]: scan.submittedContent || '',
    }));
    setResultMap((prev) => ({
      ...prev,
      [mode]: scan,
    }));
    setCurrentView('scanner');
  };

  const handleAnalyze = async () => {
    const trimmed = currentInput.trim();

    // 1. Validation Checks
    if (!trimmed) {
      switch (activeMode) {
        case ANALYSIS_TYPES.MESSAGE:
          setValidationError('Please paste or type suspicious message text before analyzing.');
          break;
        case ANALYSIS_TYPES.URL:
          setValidationError('Please enter a target URL or domain for structural analysis.');
          break;
        case ANALYSIS_TYPES.JOB_OFFER:
          setValidationError('Please paste the job offer, email pitch, or recruitment notice to analyze.');
          break;
        default:
          setValidationError('Input cannot be empty.');
      }
      return;
    }

    if (activeMode === ANALYSIS_TYPES.URL) {
      if (trimmed.includes(' ') && !trimmed.includes('http')) {
        setValidationError('URLs should not contain spaces. Please enter a valid URL or host.');
        return;
      }
    }

    // 2. Perform Analysis via Backend (or offline fallback)
    setValidationError('');
    setAnalysisError(null);
    setIsLoading(true);

    try {
      let detectionResult;
      try {
        // Primary: Dispatches to backend API (credentials: 'include' auto-attaches session cookie)
        const res = await api.scan.execute({
          type: activeMode,
          input: trimmed,
        });
        detectionResult = res.data;
      } catch (backendErr) {
        // Fallback: If backend is offline or network fails, run pure offline client detection
        console.warn('Backend scan unreachable. Executing client-side fallback detection:', backendErr.message);
        detectionResult = analyze({
          type: activeMode,
          input: trimmed,
        });
      }

      setResultMap((prev) => ({
        ...prev,
        [activeMode]: detectionResult,
      }));
    } catch (err) {
      setAnalysisError(err);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="app-shell">
      <Header
        currentView={currentView}
        onNavigate={setCurrentView}
        onOpenAuth={handleOpenAuth}
        onOpenAccount={() => setAccountModalOpen(true)}
        onOpenPrivacy={() => setPrivacyModalOpen(true)}
      />

      <main className="main-content">
        <div className="content-container">
          {/* VIEW 1: Scan History (Registered Users) */}
          {currentView === 'history' && (
            <ScanHistory
              onOpenScan={handleInspectSavedScan}
              onNewScan={() => setCurrentView('scanner')}
            />
          )}

          {/* VIEW 2: Admin Dashboard (Authorized Only) */}
          {currentView === 'admin' && (
            isAdmin ? (
              <AdminDashboard
                onClose={() => setCurrentView('scanner')}
                onOpenScanReport={handleInspectSavedScan}
              />
            ) : (
              <div className="admin-access-denied-card">
                <span className="denied-icon">🛑</span>
                <h2>Administrator Access Required</h2>
                <p>You do not possess the required credentials to access the administrative console.</p>
                <button className="scan-history-btn-primary" onClick={() => setCurrentView('scanner')}>
                  Return to Scanner
                </button>
              </div>
            )
          )}

          {/* VIEW 3: Standard Scanner */}
          {currentView === 'scanner' && (
            <>
              {/* Hero Banner */}
              <section className="hero-banner">
                <h1 className="hero-heading">Detect the Trap Before You Fall for It.</h1>
                <p className="hero-lead">
                  Analyze suspicious messages, links, and job offers with explainable threat detection.
                </p>
                <div className="retention-pill-indicator">
                  {isAuthenticated ? (
                    <span className="pill-authenticated">
                      ● Active Examiner Session • Scans Saved to Personal Archive (90-Day Retention)
                    </span>
                  ) : (
                    <span className="pill-guest">
                      🔒 Guest Examiner Mode • Zero Data Retention Guaranteed
                    </span>
                  )}
                </div>
              </section>

              {/* Mode Selector Tabs */}
              <ModeSelector
                activeMode={activeMode}
                onSelectMode={handleSelectMode}
              />

              {/* Scanner Input Panel */}
              <ScannerInput
                mode={activeMode}
                value={currentInput}
                onChange={handleInputChange}
                onAnalyze={handleAnalyze}
                onClear={handleClear}
                isLoading={isLoading}
                validationError={validationError}
              />

              {/* Error Banner */}
              {analysisError && (
                <ErrorState
                  error={analysisError}
                  onReset={handleClear}
                />
              )}

              {/* Output Display or Empty State */}
              {currentResult ? (
                <div className="result-wrapper-with-badge">
                  {currentResult.savedScanId ? (
                    <div className="scan-saved-badge">
                      <span>✓ Preserved in your personal scan archive (90-day auto-purge configured)</span>
                    </div>
                  ) : !isAuthenticated ? (
                    <div className="scan-guest-badge">
                      <span>🔒 Guest scan analyzed offline • Zero content persisted to database</span>
                    </div>
                  ) : null}
                  <ResultDisplay result={currentResult} />
                </div>
              ) : (
                <EmptyState mode={activeMode} />
              )}
            </>
          )}
        </div>
      </main>

      <footer className="app-footer">
        <div className="footer-inner">
          <div className="footer-left">
            <span className="footer-brand">TRAPSHIELD • Forensic Cybersecurity Defense Framework</span>
            <span className="footer-tagline">100% Offline Structural &amp; Heuristic Rule Analysis</span>
          </div>
          <div className="footer-right">
            <button className="footer-privacy-btn" onClick={() => setPrivacyModalOpen(true)}>
              Privacy Policy &amp; Data Retention
            </button>
          </div>
        </div>
      </footer>

      {/* Modals */}
      <AuthModal
        isOpen={authModalOpen}
        onClose={() => setAuthModalOpen(false)}
        initialMode={authModalMode}
      />

      <AccountModal
        isOpen={accountModalOpen}
        onClose={() => setAccountModalOpen(false)}
        onOpenAdmin={() => setCurrentView('admin')}
      />

      <PrivacyModal
        isOpen={privacyModalOpen}
        onClose={() => setPrivacyModalOpen(false)}
      />
    </div>
  );
}
