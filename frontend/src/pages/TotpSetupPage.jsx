import { useState } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import { AlertBanner } from '../components/AlertBanner';
import { Layout } from '../components/Layout';
import { TotpQrCard } from '../components/TotpQrCard';
import { useAuth } from '../context/AuthContext';

export function TotpSetupPage() {
  const { status, authenticated, mfaVerified, pendingTotp, confirmTotp, logout } = useAuth();
  const navigate = useNavigate();

  const [serverError, setServerError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

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

  if (mfaVerified) {
    return <Navigate to="/vault" replace />;
  }

  async function handleConfirmCode(code) {
    setServerError('');
    setIsSubmitting(true);
    try {
      await confirmTotp({ code });
      navigate('/vault', { replace: true });
    } catch (err) {
      setServerError(err.message || 'No se pudo verificar el código TOTP.');
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleRestartLogin() {
    await logout();
    navigate('/login', { replace: true });
  }

  return (
    <Layout>
      <div className="sv-auth-container">
        <section className="sv-card" aria-labelledby="totp-setup-heading">
          <h1 id="totp-setup-heading" className="sv-card-title">
            Configurar autenticación en dos pasos (TOTP)
          </h1>
          <p className="sv-card-subtitle">
            Escanea el código QR con tu aplicación autenticadora e ingresa el primer código de 6
            dígitos para activar tu bóveda y obtener tus 8 códigos de recuperación.
          </p>

          {!pendingTotp && (
            <AlertBanner
              type="info"
              message="Por seguridad, el código QR solo permanece en memoria durante la sesión actual. Si aún no lo escaneaste, vuelve a iniciar sesión para mostrarlo de nuevo."
              actionLabel="Volver a iniciar sesión"
              onAction={handleRestartLogin}
            />
          )}

          <TotpQrCard
            totp={pendingTotp}
            onSubmitCode={handleConfirmCode}
            isSubmitting={isSubmitting}
            error={serverError}
            onDismissError={() => setServerError('')}
          />
        </section>
      </div>
    </Layout>
  );
}
