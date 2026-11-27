//! Typed application error model implementing Axum's `IntoResponse`
//! without leaking internal SQL, cryptographic, or stack-trace details.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use crate::crypto::CryptoError;

/// Client-safe JSON error payload matching `contrato-api.md`.
#[derive(Debug, Serialize)]
pub struct ErrorEnvelope {
    pub success: bool,
    pub error: ErrorBody,
}

/// Structured error body returned to API clients.
#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub code: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

/// Application error taxonomy mapped to HTTP status codes and safe error codes.
#[derive(Debug, Error)]
pub enum AppError {
    /// Invalid request payload, query parameter, or domain constraint.
    #[error("validation error: {message}")]
    Validation {
        message: String,
        details: Option<Value>,
    },

    /// Missing, expired, or revoked authentication session.
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// Email or password verification failed.
    #[error("invalid credentials")]
    InvalidCredentials,

    /// Provided 6-digit TOTP code did not match.
    #[error("invalid totp code")]
    InvalidTotpCode,

    /// Provided recovery code does not exist or was already consumed.
    #[error("invalid recovery code")]
    InvalidRecoveryCode,

    /// Pre-MFA session attempted to access an MFA-protected resource.
    #[error("mfa verification required")]
    MfaRequired,

    /// Authenticated user is not allowed to perform the requested action.
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// Registration endpoint called while `ALLOW_REGISTRATION=false`.
    #[error("registration is disabled")]
    RegistrationDisabled,

    /// Missing or invalid `X-CSRF-Token` header on a state-changing request.
    #[error("csrf validation failed")]
    CsrfInvalid,

    /// Resource does not exist or belongs to another user (BOLA isolation).
    #[error("resource not found")]
    NotFound,

    /// Conflict with current resource state (e.g., duplicate email or TOTP already enabled).
    #[error("conflict ({code}): {message}")]
    Conflict { code: &'static str, message: String },

    /// Account temporarily locked after repeated authentication failures.
    #[error("account temporarily locked")]
    AccountLocked,

    /// Client IP exceeded the allowed request rate.
    #[error("rate limit exceeded")]
    RateLimited,

    /// AEAD integrity failure or missing key version (triggers webhook alert; generic 500 to client).
    #[error("cryptographic integrity failure: {0}")]
    CryptoIntegrity(String),

    /// Unexpected internal error (logged server-side; generic 500 to client).
    #[error("internal server error: {0}")]
    Internal(String),
}

impl AppError {
    /// Creates a `400 VALIDATION_ERROR` without extra details.
    #[must_use]
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation {
            message: message.into(),
            details: None,
        }
    }

    /// Creates a `400 VALIDATION_ERROR` with structured client-safe details.
    #[must_use]
    pub fn validation_with_details(message: impl Into<String>, details: Value) -> Self {
        Self::Validation {
            message: message.into(),
            details: Some(details),
        }
    }

    /// Creates a `409 Conflict` with an explicit contract error code.
    #[must_use]
    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self::Conflict {
            code,
            message: message.into(),
        }
    }

    /// Returns the HTTP status code associated with this error.
    #[must_use]
    pub const fn status_code(&self) -> StatusCode {
        match self {
            Self::Validation { .. } => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_)
            | Self::InvalidCredentials
            | Self::InvalidTotpCode
            | Self::InvalidRecoveryCode
            | Self::MfaRequired => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) | Self::RegistrationDisabled | Self::CsrfInvalid => {
                StatusCode::FORBIDDEN
            }
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict { .. } => StatusCode::CONFLICT,
            Self::AccountLocked | Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::CryptoIntegrity(_) | Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Returns the canonical contract error code.
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::Validation { .. } => "VALIDATION_ERROR",
            Self::Unauthorized(_) => "UNAUTHORIZED",
            Self::InvalidCredentials => "INVALID_CREDENTIALS",
            Self::InvalidTotpCode => "INVALID_TOTP_CODE",
            Self::InvalidRecoveryCode => "INVALID_RECOVERY_CODE",
            Self::MfaRequired => "MFA_REQUIRED",
            Self::Forbidden(_) => "FORBIDDEN",
            Self::RegistrationDisabled => "REGISTRATION_DISABLED",
            Self::CsrfInvalid => "CSRF_INVALID",
            Self::NotFound => "NOT_FOUND",
            Self::Conflict { code, .. } => code,
            Self::AccountLocked => "ACCOUNT_LOCKED",
            Self::RateLimited => "RATE_LIMITED",
            Self::CryptoIntegrity(_) | Self::Internal(_) => "INTERNAL_ERROR",
        }
    }

    /// Returns `true` for 5xx server-side errors that must trigger alerting and generic responses.
    #[must_use]
    pub const fn is_server_error(&self) -> bool {
        matches!(self, Self::CryptoIntegrity(_) | Self::Internal(_))
    }

    fn client_message(&self) -> String {
        match self {
            Self::Validation { message, .. }
            | Self::Unauthorized(message)
            | Self::Forbidden(message)
            | Self::Conflict { message, .. } => message.clone(),
            Self::InvalidCredentials => "Credenciales inválidas".to_owned(),
            Self::InvalidTotpCode => "Código TOTP inválido".to_owned(),
            Self::InvalidRecoveryCode => "Código de recuperación inválido".to_owned(),
            Self::MfaRequired => "Se requiere completar la verificación MFA".to_owned(),
            Self::RegistrationDisabled => {
                "El registro de nuevos usuarios está deshabilitado".to_owned()
            }
            Self::CsrfInvalid => "Token CSRF ausente o inválido".to_owned(),
            Self::NotFound => "Recurso no encontrado".to_owned(),
            Self::AccountLocked => {
                "Cuenta bloqueada temporalmente por demasiados intentos fallidos".to_owned()
            }
            Self::RateLimited => "Demasiadas solicitudes; inténtalo de nuevo más tarde".to_owned(),
            Self::CryptoIntegrity(_) | Self::Internal(_) => "Error interno del servidor".to_owned(),
        }
    }
}

impl From<CryptoError> for AppError {
    fn from(err: CryptoError) -> Self {
        match err {
            CryptoError::PasswordTooShort { min } => Self::validation(format!(
                "La contraseña debe tener al menos {min} caracteres"
            )),
            CryptoError::PasswordTooLong { max } => Self::validation(format!(
                "La contraseña no puede superar los {max} caracteres"
            )),
            CryptoError::IntegrityFailure
            | CryptoError::KeyVersionNotFound(_)
            | CryptoError::InvalidNonceLength => Self::CryptoIntegrity(err.to_string()),
            other => Self::Internal(other.to_string()),
        }
    }
}

/// Response extension marker indicating a `500` response already corresponds to
/// a cryptographic integrity failure (so the generic 5xx middleware avoids duplicate alerts).
#[derive(Debug, Clone, Copy)]
pub struct IsCryptoIntegrityError;

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let code = self.error_code();
        let message = self.client_message();
        let is_crypto_integrity = matches!(self, Self::CryptoIntegrity(_));

        let details = match &self {
            Self::Validation { details, .. } => details.clone(),
            Self::CryptoIntegrity(internal_msg) => {
                tracing::error!(error_code = code, detail = %internal_msg, "cryptographic integrity failure");
                None
            }
            Self::Internal(internal_msg) => {
                tracing::error!(error_code = code, detail = %internal_msg, "internal server error");
                None
            }
            _ => None,
        };

        let envelope = ErrorEnvelope {
            success: false,
            error: ErrorBody {
                code,
                message,
                details,
            },
        };

        let mut response = (status, Json(envelope)).into_response();
        if is_crypto_integrity {
            response.extensions_mut().insert(IsCryptoIntegrityError);
        }
        response
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use axum::body::to_bytes;

    use super::*;

    #[tokio::test]
    async fn internal_error_never_leaks_sensitive_details() {
        let err = AppError::Internal("sqlx error: password=supersecret relation users".to_owned());
        assert!(err.is_server_error());

        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body_bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        let json: Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(json["success"], false);
        assert_eq!(json["error"]["code"], "INTERNAL_ERROR");
        assert_eq!(json["error"]["message"], "Error interno del servidor");
        assert!(json["error"].get("details").is_none());

        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(!body_str.contains("supersecret"));
        assert!(!body_str.contains("sqlx"));
    }

    #[tokio::test]
    async fn validation_error_preserves_safe_message_and_details() {
        let err = AppError::validation_with_details(
            "Campo inválido",
            serde_json::json!({ "field": "category" }),
        );
        assert!(!err.is_server_error());

        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body_bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        let json: Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(json["success"], false);
        assert_eq!(json["error"]["code"], "VALIDATION_ERROR");
        assert_eq!(json["error"]["message"], "Campo inválido");
        assert_eq!(json["error"]["details"]["field"], "category");
    }

    #[test]
    fn maps_crypto_errors_appropriately() {
        let short_err: AppError = CryptoError::PasswordTooShort { min: 12 }.into();
        assert_eq!(short_err.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(short_err.error_code(), "VALIDATION_ERROR");

        let integrity_err: AppError = CryptoError::IntegrityFailure.into();
        assert_eq!(
            integrity_err.status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(integrity_err.is_server_error());
    }
}
