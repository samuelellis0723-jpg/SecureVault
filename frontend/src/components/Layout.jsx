import { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export function Layout({ children }) {
  const { authenticated, mfaVerified, user, logout } = useAuth();
  const [loggingOut, setLoggingOut] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();

  async function handleLogout() {
    setLoggingOut(true);
    try {
      await logout();
      navigate('/login', { replace: true });
    } finally {
      setLoggingOut(false);
    }
  }

  const brandTarget = authenticated && mfaVerified ? '/vault' : '/login';

  return (
    <div className="sv-shell">
      <a className="sv-skip-link" href="#main-content">
        Saltar al contenido principal
      </a>

      <header className="sv-header">
        <div className="sv-header-inner">
          <Link to={brandTarget} className="sv-brand">
            <svg
              className="sv-brand-icon"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <path d="M12 2L4 5v6c0 5.25 3.4 10.15 8 11 4.6-.85 8-5.75 8-11V5l-8-3z" />
              <rect x="9" y="10" width="6" height="5" rx="1" />
              <path d="M10 10V8a2 2 0 1 1 4 0v2" />
            </svg>
            <span>SecurityVault</span>
          </Link>

          <nav className="sv-nav" aria-label="Navegación principal">
            {authenticated ? (
              <>
                {user && user.email && (
                  <span className="sv-user-email" aria-label="Usuario autenticado">
                    {user.email}
                  </span>
                )}
                <button
                  type="button"
                  className="sv-btn sv-btn-ghost sv-btn-sm"
                  onClick={handleLogout}
                  disabled={loggingOut}
                >
                  {loggingOut ? 'Cerrando…' : 'Cerrar sesión'}
                </button>
              </>
            ) : (
              <>
                <Link
                  to="/login"
                  className="sv-nav-link"
                  aria-current={location.pathname === '/login' ? 'page' : undefined}
                >
                  Iniciar sesión
                </Link>
                <Link
                  to="/register"
                  className="sv-nav-link"
                  aria-current={location.pathname === '/register' ? 'page' : undefined}
                >
                  Crear cuenta
                </Link>
              </>
            )}
          </nav>
        </div>
      </header>

      <main id="main-content" className="sv-main" tabIndex={-1}>
        {children}
      </main>

      <footer className="sv-footer">
        SecurityVault · Cifrado AES-256-GCM en servidor y verificación TOTP obligatoria.
      </footer>
    </div>
  );
}
