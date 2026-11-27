import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Layout } from './Layout';

export function ProtectedRoute() {
  const { status, authenticated, mfaVerified, totpEnrolled, pendingTotp } = useAuth();

  if (status === 'loading') {
    return (
      <Layout>
        <div className="sv-status-box" role="status" aria-live="polite">
          Comprobando sesión segura…
        </div>
      </Layout>
    );
  }

  if (!authenticated) {
    return <Navigate to="/login" replace />;
  }

  if (!mfaVerified) {
    const needsSetup = !totpEnrolled || Boolean(pendingTotp);
    return <Navigate to={needsSetup ? '/totp-setup' : '/totp-verify'} replace />;
  }

  return <Outlet />;
}
