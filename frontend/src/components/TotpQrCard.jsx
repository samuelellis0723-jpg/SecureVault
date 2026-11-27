import { useState } from 'react';
import { AlertBanner } from './AlertBanner';

const TOTP_CODE_REGEX = /^\d{6}$/;

export function TotpQrCard({
  totp,
  onSubmitCode,
  isSubmitting = false,
  error = '',
  onDismissError,
}) {
  const [code, setCode] = useState('');
  const [fieldError, setFieldError] = useState('');
  const [copyStatus, setCopyStatus] = useState('');

  const qrDataUri =
    totp && typeof totp.qr_svg === 'string' && totp.qr_svg.trim().length > 0
      ? `data:image/svg+xml;charset=utf-8,${encodeURIComponent(totp.qr_svg)}`
      : null;

  async function handleCopySecret() {
    if (!totp || !totp.secret_base32) {
      return;
    }

    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(totp.secret_base32);
        setCopyStatus('Clave secreta copiada al portapapeles.');
      } else {
        setCopyStatus('Copia manualmente la clave mostrada arriba.');
      }
    } catch {
      setCopyStatus('No se pudo acceder al portapapeles. Copia la clave manualmente.');
    }
  }

  function handleSubmit(event) {
    event.preventDefault();
    const cleaned = code.trim();
    if (!TOTP_CODE_REGEX.test(cleaned)) {
      setFieldError('Ingresa un código numérico exacto de 6 dígitos.');
      return;
    }

    setFieldError('');
    onSubmitCode(cleaned);
  }

  return (
    <div>
      {totp && (
        <div className="sv-qr-wrapper">
          {qrDataUri && (
            <img
              src={qrDataUri}
              alt="Código QR para configurar autenticador TOTP"
              className="sv-qr-image"
              width="220"
              height="220"
            />
          )}

          {totp.secret_base32 && (
            <div className="sv-secret-box">
              <p className="sv-hint">
                Si no puedes escanear el QR, ingresa esta clave manual en tu aplicación autenticadora:
              </p>
              <code className="sv-secret-code">{totp.secret_base32}</code>
              <button
                type="button"
                className="sv-btn sv-btn-secondary sv-btn-sm"
                onClick={handleCopySecret}
              >
                Copiar clave manual
              </button>
              {copyStatus && (
                <p className="sv-hint" role="status" aria-live="polite">
                  {copyStatus}
                </p>
              )}
            </div>
          )}
        </div>
      )}

      <AlertBanner type="error" message={error} onDismiss={onDismissError} />

      <form className="sv-form" onSubmit={handleSubmit} noValidate>
        <div className="sv-field">
          <label htmlFor="totp-setup-code" className="sv-label">
            Código de verificación (6 dígitos)
          </label>
          <input
            id="totp-setup-code"
            name="code"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            className="sv-input sv-input-code"
            placeholder="000000"
            value={code}
            onChange={(e) => {
              setCode(e.target.value.replace(/\s+/g, ''));
              if (fieldError) setFieldError('');
            }}
            aria-invalid={Boolean(fieldError)}
            aria-describedby={fieldError ? 'totp-setup-code-error' : 'totp-setup-code-hint'}
            required
          />
          <p id="totp-setup-code-hint" className="sv-hint">
            Introduce el código de 6 dígitos generado por Google Authenticator, Authy o 2FAS.
          </p>
          {fieldError && (
            <p id="totp-setup-code-error" className="sv-field-error" role="alert">
              {fieldError}
            </p>
          )}
        </div>

        <button
          type="submit"
          className="sv-btn sv-btn-primary"
          disabled={isSubmitting}
        >
          {isSubmitting ? 'Verificando código…' : 'Confirmar y activar MFA'}
        </button>
      </form>
    </div>
  );
}
