export function AlertBanner({
  type = 'error',
  message,
  onDismiss,
  actionLabel,
  onAction,
}) {
  if (!message) {
    return null;
  }

  const isAssertive = type === 'error' || type === 'warning';
  const role = isAssertive ? 'alert' : 'status';
  const ariaLive = isAssertive ? 'assertive' : 'polite';

  return (
    <div
      className={`sv-alert sv-alert-${type}`}
      role={role}
      aria-live={ariaLive}
    >
      <p className="sv-alert-body">{message}</p>
      {(actionLabel || onDismiss) && (
        <div className="sv-alert-actions">
          {actionLabel && onAction && (
            <button
              type="button"
              className="sv-btn sv-btn-secondary sv-btn-sm"
              onClick={onAction}
            >
              {actionLabel}
            </button>
          )}
          {onDismiss && (
            <button
              type="button"
              className="sv-btn sv-btn-secondary sv-btn-sm"
              onClick={onDismiss}
              aria-label="Cerrar aviso"
            >
              Cerrar
            </button>
          )}
        </div>
      )}
    </div>
  );
}
