/**
 * TRAPSHIELD Authentication Context
 * 
 * Manages authenticated user session state, login/registration flows,
 * and automatic session restoration on app load via HTTP-only cookies.
 */

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { api } from '../api/client.js';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [isLoading, setIsLoading] = useState(true);

  // Restore session from HTTP-only cookie on mount
  const checkSession = useCallback(async () => {
    try {
      const response = await api.auth.getMe();
      if (response?.data?.user) {
        setUser(response.data.user);
      } else {
        setUser(null);
      }
    } catch {
      // 401 or network error -> treat as unauthenticated guest
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    checkSession();
  }, [checkSession]);

  const login = async ({ email, password }) => {
    const res = await api.auth.login({ email, password });
    if (res?.data?.user) {
      setUser(res.data.user);
    }
    return res.data.user;
  };

  const register = async ({ email, password }) => {
    const res = await api.auth.register({ email, password });
    if (res?.data?.user) {
      setUser(res.data.user);
    }
    return res.data.user;
  };

  const logout = async () => {
    try {
      await api.auth.logout();
    } finally {
      setUser(null);
    }
  };

  const value = {
    user,
    isAuthenticated: Boolean(user),
    isAdmin: user?.role === 'admin',
    isLoading,
    login,
    register,
    logout,
    refreshUser: checkSession,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

