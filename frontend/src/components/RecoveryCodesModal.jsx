import { useEffect, useRef, useState } from 'react';

export function RecoveryCodesModal({ codes, onConfirmSaved }) {
  const [statusMessage, setStatusMessage] = useState('');
  const titleRef = useRef(null);

  useEffect(() => {
    if (titleRef.current) {
      titleRef.current.focus();
    }
  }, []);

  if (!Array.isArray(codes) || codes.length === 0) {
    return null;
  }

  const formattedText = [
    'SecurityVault — Códigos de recuperación de un solo uso',
    'Guarda estos códigos en un lugar seguro. Cada código solo funciona una vez.',
    '',
    ...codes,
    '',
  ].join('\n');

  async function handleCopy() {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(codes.join('\n'));
        setStatusMessage('Los 8 códigos se copiaron al portapapeles.');
      } else {
        setStatusMessage('No hay acceso al portapapeles; usa la opción Descargar .txt.');
      }
    } catch {
      setStatusMessage('No se pudieron copiar los códigos. Usa la opción Descargar .txt.');
    }
  }

  function handleDownload() {
    if (typeof URL === 'undefined' || typeof URL.createObjectURL !== 'function') {
      setStatusMessage('Tu navegador no admite la descarga automática. Copia los códigos.');
      return;
    }

    const blob = new Blob([formattedText], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'securityvault-recovery-codes.txt';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    setStatusMessage('Archivo securityvault-recovery-codes.txt descargado.');
  }

  return (
    <div className="sv-modal-backdrop">
      <div
        className="sv-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="recovery-modal-title"
        aria-describedby="recovery-modal-desc"
      >
        <h2
          id="recovery-modal-title"
          ref={titleRef}
          tabIndex={-1}
          className="sv-card-title"
        >
          Guarda tus códigos de recuperación
        </h2>
        <p id="recovery-modal-desc" className="sv-card-subtitle">
          Estos {codes.length} códigos de un solo uso se muestran una única vez. Úsalos si pierdes
          acceso a tu aplicación autenticadora TOTP.
        </p>

        <ol className="sv-recovery-list" aria-label="Lista de códigos de recuperación">
          {codes.map((recoveryCode) => (
            <li key={recoveryCode}>
              <code className="sv-recovery-code">{recoveryCode}</code>
            </li>
          ))}
        </ol>

        {statusMessage && (
          <p className="sv-hint" role="status" aria-live="polite">
            {statusMessage}
          </p>
        )}

        <div className="sv-actions">
          <button
            type="button"
            className="sv-btn sv-btn-secondary"
            onClick={handleCopy}
          >
            Copiar códigos
          </button>
          <button
            type="button"
            className="sv-btn sv-btn-secondary"
            onClick={handleDownload}
          >
            Descargar .txt
          </button>
          <button
            type="button"
            className="sv-btn sv-btn-primary"
            onClick={onConfirmSaved}
          >
            Ya los guardé
          </button>
        </div>
      </div>
    </div>
  );
}
