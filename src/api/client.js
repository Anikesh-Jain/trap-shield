/**
 * TRAPSHIELD Centralized API Client
 * 
 * SECURITY MANDATE:
 * - Always includes credentials for secure HTTP-only cookie session handling.
 * - Centralizes error parsing, status mapping, and endpoint contracts.
 */

let rawBase = (import.meta.env?.VITE_API_BASE_URL || '/api/v1').trim().replace(/\/+$/, '');
// Ensure /api/v1 prefix is appended if an origin root was configured without path
if (rawBase && !rawBase.endsWith('/api/v1') && !rawBase.includes('/api/')) {
  rawBase = `${rawBase}/api/v1`;
}
const BASE_URL = rawBase;

async function apiRequest(endpoint, options = {}) {
  const url = `${BASE_URL}${endpoint.startsWith('/') ? endpoint : `/${endpoint}`}`;
  
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };

  const config = {
    ...options,
    headers,
    credentials: 'include', // CRITICAL: ensures HTTP-only auth cookies are sent
  };

  if (config.body && typeof config.body === 'object' && !(config.body instanceof FormData)) {
    config.body = JSON.stringify(config.body);
  }

  let response;
  try {
    response = await fetch(url, config);
  } catch (netErr) {
    const error = new Error('Network connection failed. Please ensure TRAPSHIELD backend server is running.');
    error.statusCode = 0;
    error.errorCode = 'NETWORK_ERROR';
    throw error;
  }

  let data;
  try {
    data = await response.json();
  } catch {
    data = null;
  }

  if (!response.ok) {
    const errorMessage = data?.message || `Request failed with status ${response.status}`;
    const error = new Error(errorMessage);
    error.statusCode = response.status;
    error.errorCode = data?.errorCode || 'REQUEST_FAILED';
    error.details = data?.details || null;
    throw error;
  }

  return data;
}

export const api = {
  // Authentication
  auth: {
    register: ({ email, password }) =>
      apiRequest('/auth/register', { method: 'POST', body: { email, password } }),
    login: ({ email, password }) =>
      apiRequest('/auth/login', { method: 'POST', body: { email, password } }),
    logout: () =>
      apiRequest('/auth/logout', { method: 'POST' }),
    getMe: () =>
      apiRequest('/auth/me', { method: 'GET' }),
  },

  // Scanning & History
  scan: {
    execute: ({ type, input }) =>
      apiRequest('/scan', { method: 'POST', body: { type, input } }),
    getHistory: ({ page = 1, limit = 10 } = {}) =>
      apiRequest(`/scan/history?page=${page}&limit=${limit}`, { method: 'GET' }),
    getById: (id) =>
      apiRequest(`/scan/history/${id}`, { method: 'GET' }),
    deleteById: (id) =>
      apiRequest(`/scan/history/${id}`, { method: 'DELETE' }),
  },

  // Administrator Controls
  admin: {
    getStats: () =>
      apiRequest('/admin/stats', { method: 'GET' }),
    getUsers: ({ page = 1, limit = 20 } = {}) =>
      apiRequest(`/admin/users?page=${page}&limit=${limit}`, { method: 'GET' }),
    getUserScans: (userId) =>
      apiRequest(`/admin/users/${userId}/scans`, { method: 'GET' }),
    updateUserStatus: (userId, isActive) =>
      apiRequest(`/admin/users/${userId}/status`, { method: 'PATCH', body: { isActive } }),
    getAuditLogs: () =>
      apiRequest('/admin/audit-logs', { method: 'GET' }),
  },

  // Privacy & Transparency
  privacy: {
    getPolicy: () =>
      apiRequest('/privacy', { method: 'GET' }),
  },

  // System Health
  health: {
    check: () =>
      apiRequest('/health', { method: 'GET' }),
  },
};

