import { useState } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import { AlertBanner } from '../components/AlertBanner';
import { Layout } from '../components/Layout';
import { useAuth } from '../context/AuthContext';

const TOTP_CODE_REGEX = /^\d{6}$/;
const RECOVERY_CODE_REGEX = /^[A-Za-z0-9]{4}-?[A-Za-z0-9]{4}$/;

export function TotpVerifyPage() {
  const { status, authenticated, mfaVerified, verifyTotp, logout } = useAuth();
  const navigate = useNavigate();

  const [useRecoveryMode, setUseRecoveryMode] = useState(false);
  const [inputValue, setInputValue] = useState('');
  const [fieldError, setFieldError] = useState('');
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

  function handleToggleMode() {
    setUseRecoveryMode((prev) => !prev);
    setInputValue('');
    setFieldError('');
    setServerError('');
  }

  async function handleSubmit(event) {
    event.preventDefault();
    const cleaned = inputValue.trim();

    if (useRecoveryMode) {
      if (!RECOVERY_CODE_REGEX.test(cleaned)) {
        setFieldError('Ingresa un código de recuperación válido con formato XXXX-XXXX.');
        return;
      }
    } else if (!TOTP_CODE_REGEX.test(cleaned)) {
      setFieldError('Ingresa un código numérico exacto de 6 dígitos.');
      return;
    }

    setFieldError('');
    setServerError('');
    setIsSubmitting(true);

    try {
      if (useRecoveryMode) {
        await verifyTotp({ recoveryCode: cleaned.toUpperCase() });
      } else {
        await verifyTotp({ code: cleaned });
      }
      navigate('/vault', { replace: true });
    } catch (err) {
      setServerError(err.message || 'No se pudo completar la verificación.');
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleBackToLogin() {
    await logout();
    navigate('/login', { replace: true });
  }

  return (
    <Layout>
      <div className="sv-auth-container">
        <section className="sv-card" aria-labelledby="totp-verify-heading">
          <h1 id="totp-verify-heading" className="sv-card-title">
            Verificación en dos pasos
          </h1>
          <p className="sv-card-subtitle">
            {useRecoveryMode
              ? 'Ingresa uno de tus códigos de recuperación de un solo uso (formato XXXX-XXXX).'
              : 'Paso 2 de 2: ingresa el código de 6 dígitos de tu aplicación autenticadora.'}
          </p>

          <AlertBanner
            type="error"
            message={serverError}
            onDismiss={() => setServerError('')}
          />

          <form className="sv-form" onSubmit={handleSubmit} noValidate>
            <div className="sv-field">
              <label htmlFor="mfa-code-input" className="sv-label">
                {useRecoveryMode
                  ? 'Código de recuperación (XXXX-XXXX)'
                  : 'Código TOTP (6 dígitos)'}
              </label>
              <input
                id="mfa-code-input"
                name={useRecoveryMode ? 'recovery_code' : 'code'}
                type="text"
                inputMode={useRecoveryMode ? 'text' : 'numeric'}
                autoComplete={useRecoveryMode ? 'off' : 'one-time-code'}
                maxLength={useRecoveryMode ? 9 : 6}
                className="sv-input sv-input-code"
                placeholder={useRecoveryMode ? 'ABCD-EFGH' : '000000'}
                value={inputValue}
                onChange={(e) => {
                  setInputValue(e.target.value.replace(/\s+/g, ''));
                  if (fieldError) setFieldError('');
                }}
                aria-invalid={Boolean(fieldError)}
                aria-describedby={fieldError ? 'mfa-code-error' : undefined}
                required
              />
              {fieldError && (
                <p id="mfa-code-error" className="sv-field-error" role="alert">
                  {fieldError}
                </p>
              )}
            </div>

            <button
              type="submit"
              className="sv-btn sv-btn-primary"
              disabled={isSubmitting}
            >
              {isSubmitting ? 'Verificando…' : 'Verificar y abrir bóveda'}
            </button>
          </form>

          <div className="sv-auth-footer sv-actions">
            <button
              type="button"
              className="sv-btn-link"
              onClick={handleToggleMode}
            >
              {useRecoveryMode
                ? 'Usar código del autenticador (6 dígitos)'
                : 'Usar código de recuperación'}
            </button>
            <button
              type="button"
              className="sv-btn sv-btn-secondary sv-btn-sm"
              onClick={handleBackToLogin}
            >
              Volver a iniciar sesión
            </button>
          </div>
        </section>
      </div>
    </Layout>
  );
}
