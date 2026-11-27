import { useState } from 'react';
import { Link, Navigate, useNavigate } from 'react-router-dom';
import { AlertBanner } from '../components/AlertBanner';
import { Layout } from '../components/Layout';
import { useAuth } from '../context/AuthContext';

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MIN_PASSWORD_LENGTH = 12;
const MAX_PASSWORD_LENGTH = 128;

export function RegisterPage() {
  const { status, authenticated, mfaVerified, register } = useAuth();
  const navigate = useNavigate();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
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

    if (!trimmedEmail || trimmedEmail.length > 254 || !EMAIL_REGEX.test(trimmedEmail)) {
      errors.email = 'Ingresa un correo electrónico válido (máximo 254 caracteres).';
    }

    if (password.length < MIN_PASSWORD_LENGTH || password.length > MAX_PASSWORD_LENGTH) {
      errors.password = `La contraseña debe tener entre ${MIN_PASSWORD_LENGTH} y ${MAX_PASSWORD_LENGTH} caracteres.`;
    }

    if (password !== confirmPassword) {
      errors.confirmPassword = 'Las contraseñas no coinciden.';
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
      await register({ email, password });
      navigate('/totp-setup', { replace: true });
    } catch (err) {
      setServerError(err.message || 'No se pudo crear la cuenta.');
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <Layout>
      <div className="sv-auth-container">
        <section className="sv-card" aria-labelledby="register-heading">
          <h1 id="register-heading" className="sv-card-title">
            Crear cuenta
          </h1>
          <p className="sv-card-subtitle">
            Crea tu bóveda privada. En el siguiente paso configurarás tu autenticador TOTP obligatorio.
          </p>

          <AlertBanner
            type="error"
            message={serverError}
            onDismiss={() => setServerError('')}
          />

          <form className="sv-form" onSubmit={handleSubmit} noValidate>
            <div className="sv-field">
              <label htmlFor="register-email" className="sv-label">
                Correo electrónico
              </label>
              <input
                id="register-email"
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
                aria-describedby={fieldErrors.email ? 'register-email-error' : undefined}
                required
              />
              {fieldErrors.email && (
                <p id="register-email-error" className="sv-field-error" role="alert">
                  {fieldErrors.email}
                </p>
              )}
            </div>

            <div className="sv-field">
              <label htmlFor="register-password" className="sv-label">
                Contraseña maestra
              </label>
              <input
                id="register-password"
                name="password"
                type="password"
                autoComplete="new-password"
                maxLength={MAX_PASSWORD_LENGTH}
                className="sv-input"
                value={password}
                onChange={(e) => {
                  setPassword(e.target.value);
                  if (fieldErrors.password) {
                    setFieldErrors((prev) => ({ ...prev, password: '' }));
                  }
                }}
                aria-invalid={Boolean(fieldErrors.password)}
                aria-describedby={
                  fieldErrors.password ? 'register-password-error' : 'register-password-hint'
                }
                required
              />
              <p id="register-password-hint" className="sv-hint">
                Usa una frase segura de entre 12 y 128 caracteres.
              </p>
              {fieldErrors.password && (
                <p id="register-password-error" className="sv-field-error" role="alert">
                  {fieldErrors.password}
                </p>
              )}
            </div>

            <div className="sv-field">
              <label htmlFor="register-confirm-password" className="sv-label">
                Confirmar contraseña
              </label>
              <input
                id="register-confirm-password"
                name="confirmPassword"
                type="password"
                autoComplete="new-password"
                maxLength={MAX_PASSWORD_LENGTH}
                className="sv-input"
                value={confirmPassword}
                onChange={(e) => {
                  setConfirmPassword(e.target.value);
                  if (fieldErrors.confirmPassword) {
                    setFieldErrors((prev) => ({ ...prev, confirmPassword: '' }));
                  }
                }}
                aria-invalid={Boolean(fieldErrors.confirmPassword)}
                aria-describedby={
                  fieldErrors.confirmPassword ? 'register-confirm-error' : undefined
                }
                required
              />
              {fieldErrors.confirmPassword && (
                <p id="register-confirm-error" className="sv-field-error" role="alert">
                  {fieldErrors.confirmPassword}
                </p>
              )}
            </div>

            <button
              type="submit"
              className="sv-btn sv-btn-primary"
              disabled={isSubmitting}
            >
              {isSubmitting ? 'Creando cuenta…' : 'Crear cuenta y configurar MFA'}
            </button>
          </form>

          <p className="sv-auth-footer">
            ¿Ya tienes una cuenta? <Link to="/login">Iniciar sesión</Link>
          </p>
        </section>
      </div>
    </Layout>
  );
}
