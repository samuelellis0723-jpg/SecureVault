import { useState } from 'react';
import { Link, Navigate, useNavigate } from 'react-router-dom';
import { AlertBanner } from '../components/AlertBanner';
import { Layout } from '../components/Layout';
import { useAuth } from '../context/AuthContext';

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function LoginPage() {
  const { status, authenticated, mfaVerified, login } = useAuth();
  const navigate = useNavigate();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [fieldErrors, setFieldErrors] = useState({});
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

  if (authenticated && mfaVerified) {
    return <Navigate to="/vault" replace />;
  }

  function validate() {
    const errors = {};
    const trimmedEmail = email.trim();
    if (!trimmedEmail || !EMAIL_REGEX.test(trimmedEmail)) {
      errors.email = 'Ingresa un correo electrónico válido.';
    }
    if (!password) {
      errors.password = 'Ingresa tu contraseña.';
    }
    return errors;
  }

  async function handleSubmit(event) {
    event.preventDefault();
    const errors = validate();
    if (Object.keys(errors).length > 0) {
      setFieldErrors(errors);
      return;
    }

    setFieldErrors({});
    setServerError('');
    setIsSubmitting(true);

    try {
      const data = await login({ email, password });
      if (data && data.totp_enrolled === false) {
        navigate('/totp-setup', { replace: true });
      } else {
        navigate('/totp-verify', { replace: true });
      }
    } catch (err) {
      setServerError(err.message || 'No se pudo iniciar sesión.');
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <Layout>
      <div className="sv-auth-container">
        <section className="sv-card" aria-labelledby="login-heading">
          <h1 id="login-heading" className="sv-card-title">
            Iniciar sesión
          </h1>
          <p className="sv-card-subtitle">
            Paso 1 de 2: ingresa tus credenciales para continuar con la verificación TOTP.
          </p>

          <AlertBanner
            type="error"
            message={serverError}
            onDismiss={() => setServerError('')}
          />

          <form className="sv-form" onSubmit={handleSubmit} noValidate>
            <div className="sv-field">
              <label htmlFor="login-email" className="sv-label">
                Correo electrónico
              </label>
              <input
                id="login-email"
                name="email"
                type="email"
                autoComplete="email"
                maxLength={254}
                className="sv-input"
                value={email}
                onChange={(e) => {
                  setEmail(e.target.value);
                  if (fieldErrors.email) {
                    setFieldErrors((prev) => ({ ...prev, email: '' }));
                  }
                }}
                aria-invalid={Boolean(fieldErrors.email)}
                aria-describedby={fieldErrors.email ? 'login-email-error' : undefined}
                required
              />
              {fieldErrors.email && (
                <p id="login-email-error" className="sv-field-error" role="alert">
                  {fieldErrors.email}
                </p>
              )}
            </div>

            <div className="sv-field">
              <label htmlFor="login-password" className="sv-label">
                Contraseña
              </label>
              <div className="sv-input-group">
                <input
                  id="login-password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="current-password"
                  maxLength={128}
                  className="sv-input"
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    if (fieldErrors.password) {
                      setFieldErrors((prev) => ({ ...prev, password: '' }));
                    }
                  }}
                  aria-invalid={Boolean(fieldErrors.password)}
                  aria-describedby={fieldErrors.password ? 'login-password-error' : undefined}
                  required
                />
                <button
                  type="button"
                  className="sv-btn sv-btn-secondary sv-btn-sm"
                  onClick={() => setShowPassword((prev) => !prev)}
                  aria-pressed={showPassword}
                >
                  {showPassword ? 'Ocultar' : 'Mostrar'}
                </button>
              </div>
              {fieldErrors.password && (
                <p id="login-password-error" className="sv-field-error" role="alert">
                  {fieldErrors.password}
                </p>
              )}
            </div>

            <button
              type="submit"
              className="sv-btn sv-btn-primary"
              disabled={isSubmitting}
            >
              {isSubmitting ? 'Verificando…' : 'Continuar'}
            </button>
          </form>

          <p className="sv-auth-footer">
            ¿Aún no tienes una cuenta? <Link to="/register">Crear cuenta</Link>
          </p>
        </section>
      </div>
    </Layout>
  );
}
