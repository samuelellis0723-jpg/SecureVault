import { createContext, useContext, useEffect, useState } from 'react';
import { authApi, clearCsrfToken } from '../api/client';

const AuthContext = createContext(null);

const INITIAL_STATE = {
  status: 'loading',
  authenticated: false,
  user: null,
};

const UNAUTHENTICATED_STATE = {
  status: 'ready',
  authenticated: false,
  user: null,
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
          user: data.user || null,
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
      user: data.user || { email: email.trim().toLowerCase() },
    });
    return data;
  }

  async function login({ email, password }) {
    const data = await authApi.login({ email, password });
    setAuthState({
      status: 'ready',
      authenticated: true,
      user: data.user || { email: email.trim().toLowerCase() },
    });
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

  function resetSession() {
    clearCsrfToken();
    setAuthState(UNAUTHENTICATED_STATE);
  }

  const value = {
    ...authState,
    register,
    login,
    logout,
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
