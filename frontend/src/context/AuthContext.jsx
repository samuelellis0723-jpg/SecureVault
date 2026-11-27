import { createContext, useContext, useEffect, useState } from 'react';
import { authApi, clearCsrfToken } from '../api/client';

const AuthContext = createContext(null);

const INITIAL_STATE = {
  status: 'loading',
  authenticated: false,
  mfaVerified: false,
  totpEnrolled: false,
  user: null,
  pendingTotp: null,
  recoveryCodes: null,
};

const UNAUTHENTICATED_STATE = {
  status: 'ready',
  authenticated: false,
  mfaVerified: false,
  totpEnrolled: false,
  user: null,
  pendingTotp: null,
  recoveryCodes: null,
};

export function AuthProvider({ children }) {
  const [authState, setAuthState] = useState(INITIAL_STATE);

  useEffect(() => {
    const controller = new AbortController();

    authApi
      .me({ signal: controller.signal })
      .then((data) => {
        setAuthState({
          status: 'ready',
          authenticated: Boolean(data.authenticated),
          mfaVerified: Boolean(data.mfa_verified),
          totpEnrolled: Boolean(data.user && data.user.totp_enabled),
          user: data.user || null,
          pendingTotp: null,
          recoveryCodes: null,
        });
      })
      .catch((err) => {
        if (err && err.name === 'AbortError') {
          return;
        }
        clearCsrfToken();
        setAuthState(UNAUTHENTICATED_STATE);
      });

    return () => controller.abort();
  }, []);

  async function register({ email, password }) {
    const data = await authApi.register({ email, password });
    setAuthState({
      status: 'ready',
      authenticated: true,
      mfaVerified: false,
      totpEnrolled: false,
      user: {
        email: email.trim().toLowerCase(),
        totp_enabled: false,
      },
      pendingTotp: data.totp || null,
      recoveryCodes: null,
    });
    return data;
  }

  async function login({ email, password }) {
    const data = await authApi.login({ email, password });
    const enrolled = Boolean(data.totp_enrolled);
    setAuthState({
      status: 'ready',
      authenticated: true,
      mfaVerified: false,
      totpEnrolled: enrolled,
      user: {
        email: email.trim().toLowerCase(),
        totp_enabled: enrolled,
      },
      pendingTotp: data.totp || null,
      recoveryCodes: null,
    });
    return data;
  }

  async function confirmTotp({ code }) {
    const data = await authApi.confirmTotp({ code });
    setAuthState({
      status: 'ready',
      authenticated: true,
      mfaVerified: true,
      totpEnrolled: true,
      user: data.user || null,
      pendingTotp: null,
      recoveryCodes: Array.isArray(data.recovery_codes) ? data.recovery_codes : null,
    });
    return data;
  }

  async function verifyTotp({ code, recoveryCode }) {
    const data = await authApi.verifyTotp({ code, recoveryCode });
    setAuthState((prev) => ({
      ...prev,
      status: 'ready',
      authenticated: true,
      mfaVerified: true,
      totpEnrolled: true,
      user: data.user || prev.user,
      pendingTotp: null,
    }));
    return data;
  }

  async function logout() {
    try {
      await authApi.logout();
    } catch {
      // Si la sesión ya expiró en servidor, igualmente limpiamos el estado local en memoria.
      clearCsrfToken();
    } finally {
      setAuthState(UNAUTHENTICATED_STATE);
    }
  }

  function clearRecoveryCodes() {
    setAuthState((prev) => ({
      ...prev,
      recoveryCodes: null,
    }));
  }

  function resetSession() {
    clearCsrfToken();
    setAuthState(UNAUTHENTICATED_STATE);
  }

  const value = {
    ...authState,
    register,
    login,
    confirmTotp,
    verifyTotp,
    logout,
    clearRecoveryCodes,
    resetSession,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth debe utilizarse dentro de un AuthProvider.');
  }
  return ctx;
}
