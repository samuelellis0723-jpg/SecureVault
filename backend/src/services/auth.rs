//! Authentication, session management, CSRF, and brute-force lockout service.

use rand::{RngCore, rngs::OsRng};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use subtle::ConstantTimeEq;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{
    cipher::{AAD_ENTITY_TOTP_SECRET, KeyRing},
    password::{hash_password, validate_password, verify_password},
    totp::{generate_totp_secret, keyed_sha256_bytes, keyed_sha256_hex, sha256_bytes},
};
use crate::domain::{
    error::AppError,
    models::{AuthAttemptRecord, AuthAttemptType, SessionRecord, UserPublic, UserRecord},
};
use crate::repositories::VaultRepositories;
use crate::services::alerts::{AlertEventKind, AlertService};

/// Full authenticated session absolute lifetime (8 hours).
pub const FULL_SESSION_TTL_SECS: i64 = 8 * 60 * 60;

/// Full authenticated session inactivity timeout (30 minutes).
pub const SESSION_INACTIVITY_TTL_SECS: i64 = 30 * 60;

/// Consecutive/window failure threshold triggering a 15-minute lockout and webhook alert.
pub const MAX_AUTH_FAILURES: i16 = 5;

/// Sliding window and lockout duration (15 minutes).
pub const LOCKOUT_WINDOW_MINUTES: i64 = 15;

/// Maximum allowed email length per RFC 5321.
const MAX_EMAIL_LEN: usize = 254;

/// Maximum allowed password byte length during login to avoid excessive hashing payloads.
const MAX_LOGIN_PASSWORD_BYTES: usize = 512;

/// Valid pre-computed Argon2id PHC hash (`m=19456, t=2, p=1`) used for constant-time
/// dummy verification when a login email does not exist (anti-enumeration timing defense).
const DUMMY_ARGON2_PHC_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2VjdXJpdHl2YXVsdGR1bW15$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Validated session resolved from the `sv_session` cookie.
#[derive(Clone)]
pub struct AuthenticatedSession {
    pub session: SessionRecord,
    pub raw_token: SecretString,
}

/// Output of `POST /api/v1/auth/register` and `POST /api/v1/auth/login`.
pub struct AuthSessionOutput {
    pub user: UserPublic,
    pub session_token: SecretString,
    pub session_max_age_secs: i64,
    pub csrf_token: String,
}

/// Output of `GET /api/v1/auth/me`.
#[derive(Debug, Clone, Serialize)]
pub struct MeOutput {
    pub authenticated: bool,
    pub user: UserPublic,
    pub csrf_token: String,
}

/// Core authentication, session, CSRF, and lockout service.
#[derive(Clone)]
pub struct AuthService {
    repos: VaultRepositories,
    key_ring: KeyRing,
    pepper: SecretString,
    allow_registration: bool,
    alerts: AlertService,
}

impl AuthService {
    /// Creates a new [`AuthService`].
    #[must_use]
    pub const fn new(
        repos: VaultRepositories,
        key_ring: KeyRing,
        pepper: SecretString,
        allow_registration: bool,
        alerts: AlertService,
    ) -> Self {
        Self {
            repos,
            key_ring,
            pepper,
            allow_registration,
            alerts,
        }
    }

    /// Registers a new user (when `ALLOW_REGISTRATION=true`), persists schema-compatible
    /// encrypted placeholder bytes in `totp_secret_*` with `totp_enabled = false`,
    /// and immediately opens a full authenticated session (8h absolute / 30min inactivity).
    pub async fn register(
        &self,
        email: &str,
        password: SecretString,
    ) -> Result<AuthSessionOutput, AppError> {
        if !self.allow_registration {
            return Err(AppError::RegistrationDisabled);
        }

        let normalized_email = normalize_and_validate_email(email)?;
        validate_password(password.expose_secret())?;

        let password_hash = hash_password(password).await?;
        let user_id = Uuid::new_v4();

        // Keep full compatibility with the existing PostgreSQL schema constraints
        // (NOT NULL ciphertext + 12-byte nonce + key_version >= 1) without requiring migrations.
        let raw_totp_placeholder = generate_totp_secret();
        let encrypted_totp = self.key_ring.encrypt(
            &raw_totp_placeholder[..],
            user_id,
            AAD_ENTITY_TOTP_SECRET,
            user_id,
        )?;

        let now = OffsetDateTime::now_utc();
        let user = UserRecord {
            id: user_id,
            email: normalized_email,
            password_hash,
            totp_secret_ciphertext: encrypted_totp.ciphertext,
            totp_secret_nonce: encrypted_totp.nonce.to_vec(),
            totp_key_version: encrypted_totp.key_version,
            totp_enabled: false,
            failed_login_attempts: 0,
            locked_until: None,
            created_at: now,
            updated_at: now,
        };

        let created = self.repos.users.create_user(user).await?;
        let (session_token, csrf_token) = self
            .issue_session(created.id, true, FULL_SESSION_TTL_SECS)
            .await?;

        Ok(AuthSessionOutput {
            user: UserPublic::from(&created),
            session_token,
            session_max_age_secs: FULL_SESSION_TTL_SECS,
            csrf_token,
        })
    }

    /// Verifies email + password (with Argon2id timing-attack mitigation for missing users),
    /// enforces brute-force lockout, and opens a full authenticated session (8h absolute / 30min inactivity).
    pub async fn login(
        &self,
        email: &str,
        password: SecretString,
        client_ip: &str,
        request_id: &str,
    ) -> Result<AuthSessionOutput, AppError> {
        let normalized_email = normalize_and_validate_email(email)?;
        if password.expose_secret().is_empty()
            || password.expose_secret().len() > MAX_LOGIN_PASSWORD_BYTES
        {
            return Err(AppError::validation("Contraseña inválida"));
        }

        let now = OffsetDateTime::now_utc();
        let identifier_hash = self.hash_identifier(&normalized_email)?;
        let ip_hash = self.hash_ip(client_ip)?;

        let user_opt = self
            .repos
            .users
            .find_user_by_email(&normalized_email)
            .await?;

        if let Some(ref user) = user_opt
            && is_locked(user, now)
        {
            return Err(AppError::AccountLocked);
        }

        let valid = if let Some(user) = &user_opt {
            verify_password(password, user.password_hash.clone()).await?
        } else {
            // Execute dummy Argon2id verification so missing accounts take comparable CPU time.
            let _ = verify_password(password, SecretString::from(DUMMY_ARGON2_PHC_HASH)).await;
            false
        };

        self.repos
            .auth_attempts
            .record_attempt(AuthAttemptRecord {
                id: Uuid::new_v4(),
                identifier_hash,
                ip_hash,
                attempt_type: AuthAttemptType::Login,
                succeeded: valid,
                created_at: now,
            })
            .await?;

        if !valid {
            let locked = self
                .record_failure_and_check_lockout(
                    user_opt.as_ref(),
                    identifier_hash,
                    now,
                    client_ip,
                    request_id,
                )
                .await?;
            if locked {
                return Err(AppError::AccountLocked);
            }
            return Err(AppError::InvalidCredentials);
        }

        let Some(user) = user_opt else {
            return Err(AppError::InvalidCredentials);
        };

        self.repos.users.reset_login_failures(user.id).await?;
        let (session_token, csrf_token) = self
            .issue_session(user.id, true, FULL_SESSION_TTL_SECS)
            .await?;

        Ok(AuthSessionOutput {
            user: UserPublic::from(&user),
            session_token,
            session_max_age_secs: FULL_SESSION_TTL_SECS,
            csrf_token,
        })
    }

    /// Revokes the active session on the server.
    pub async fn logout(&self, auth_session: &AuthenticatedSession) -> Result<(), AppError> {
        let now = OffsetDateTime::now_utc();
        self.repos
            .sessions
            .revoke_session(auth_session.session.id, now)
            .await
    }

    /// Resolves and validates a session from the opaque cookie token, enforcing
    /// completion (`mfa_verified = true`), absolute expiration, revocation,
    /// and 30-minute inactivity timeout.
    pub async fn authenticate_session(
        &self,
        raw_token: &str,
    ) -> Result<AuthenticatedSession, AppError> {
        let trimmed = raw_token.trim();
        if trimmed.is_empty() {
            return Err(AppError::Unauthorized("Sesión requerida".to_owned()));
        }

        let token_hash = sha256_bytes(trimmed.as_bytes());
        let session = self
            .repos
            .sessions
            .find_session_by_token_hash(token_hash)
            .await?
            .ok_or_else(|| AppError::Unauthorized("Sesión inválida o expirada".to_owned()))?;

        let now = OffsetDateTime::now_utc();
        if session.revoked_at.is_some() || session.expires_at <= now || !session.mfa_verified {
            return Err(AppError::Unauthorized(
                "Sesión revocada o expirada".to_owned(),
            ));
        }

        let inactivity_deadline =
            session.last_seen_at + Duration::seconds(SESSION_INACTIVITY_TTL_SECS);
        if inactivity_deadline <= now {
            return Err(AppError::Unauthorized(
                "Sesión expirada por inactividad".to_owned(),
            ));
        }
        self.repos.sessions.touch_session(session.id, now).await?;

        Ok(AuthenticatedSession {
            session,
            raw_token: SecretString::from(trimmed.to_owned()),
        })
    }

    /// Returns current session status and re-derived CSRF token for SPA rehydration.
    pub async fn me(&self, auth_session: &AuthenticatedSession) -> Result<MeOutput, AppError> {
        let user = self
            .repos
            .users
            .find_user_by_id(auth_session.session.user_id)
            .await?
            .ok_or_else(|| AppError::Unauthorized("Sesión no válida".to_owned()))?;

        let csrf_token = self.derive_csrf_token(
            auth_session.session.id,
            auth_session.raw_token.expose_secret(),
        )?;
        let derived_hash = sha256_bytes(csrf_token.as_bytes());
        if !bool::from(derived_hash.ct_eq(&auth_session.session.csrf_token_hash)) {
            return Err(AppError::Unauthorized("Sesión inconsistente".to_owned()));
        }

        Ok(MeOutput {
            authenticated: true,
            user: UserPublic::from(&user),
            csrf_token,
        })
    }

    /// Validates `X-CSRF-Token` against `session.csrf_token_hash` in constant time.
    pub fn verify_csrf(
        &self,
        session: &SessionRecord,
        provided_csrf: Option<&str>,
    ) -> Result<(), AppError> {
        let Some(raw) = provided_csrf.map(str::trim).filter(|s| !s.is_empty()) else {
            return Err(AppError::CsrfInvalid);
        };
        let provided_hash = sha256_bytes(raw.as_bytes());
        if bool::from(provided_hash.ct_eq(&session.csrf_token_hash)) {
            Ok(())
        } else {
            Err(AppError::CsrfInvalid)
        }
    }

    async fn issue_session(
        &self,
        user_id: Uuid,
        mfa_verified: bool,
        ttl_secs: i64,
    ) -> Result<(SecretString, String), AppError> {
        let session_id = Uuid::new_v4();
        let raw_token = generate_opaque_token();
        let token_hash = sha256_bytes(raw_token.expose_secret().as_bytes());
        let csrf_token = self.derive_csrf_token(session_id, raw_token.expose_secret())?;
        let csrf_token_hash = sha256_bytes(csrf_token.as_bytes());

        let now = OffsetDateTime::now_utc();
        let session = SessionRecord {
            id: session_id,
            user_id,
            token_hash,
            csrf_token_hash,
            mfa_verified,
            last_seen_at: now,
            expires_at: now + Duration::seconds(ttl_secs),
            revoked_at: None,
            created_at: now,
        };

        self.repos.sessions.create_session(session).await?;
        Ok((raw_token, csrf_token))
    }

    fn derive_csrf_token(&self, session_id: Uuid, raw_token: &str) -> Result<String, AppError> {
        let material = Zeroizing::new(format!("{session_id}:{raw_token}"));
        keyed_sha256_hex(&self.pepper, "csrf-token", &material).map_err(AppError::from)
    }

    fn hash_identifier(&self, email_lower: &str) -> Result<[u8; 32], AppError> {
        keyed_sha256_bytes(&self.pepper, "auth-identifier", email_lower).map_err(AppError::from)
    }

    fn hash_ip(&self, client_ip: &str) -> Result<[u8; 32], AppError> {
        keyed_sha256_bytes(&self.pepper, "auth-ip", client_ip.trim()).map_err(AppError::from)
    }

    async fn record_failure_and_check_lockout(
        &self,
        user_opt: Option<&UserRecord>,
        identifier_hash: [u8; 32],
        now: OffsetDateTime,
        client_ip: &str,
        request_id: &str,
    ) -> Result<bool, AppError> {
        let window_start = now - Duration::minutes(LOCKOUT_WINDOW_MINUTES);
        let recent_failures = self
            .repos
            .auth_attempts
            .count_recent_failures(identifier_hash, window_start)
            .await?;

        let threshold_u64 = u64::try_from(MAX_AUTH_FAILURES).unwrap_or(5);

        if let Some(user) = user_opt {
            let base_failures = if user.locked_until.is_some_and(|until| until <= now) {
                0
            } else {
                user.failed_login_attempts
            };
            let new_failures = base_failures.saturating_add(1);
            let should_lock = new_failures >= MAX_AUTH_FAILURES || recent_failures >= threshold_u64;
            let locked_until = if should_lock {
                Some(now + Duration::minutes(LOCKOUT_WINDOW_MINUTES))
            } else {
                None
            };

            self.repos
                .users
                .update_login_failure(user.id, new_failures, locked_until)
                .await?;

            if should_lock {
                self.alerts.notify(
                    AlertEventKind::AuthBruteforce,
                    request_id,
                    client_ip,
                    "ACCOUNT_LOCKED",
                );
                return Ok(true);
            }
            return Ok(false);
        }

        if recent_failures >= threshold_u64 {
            self.alerts.notify(
                AlertEventKind::AuthBruteforce,
                request_id,
                client_ip,
                "ACCOUNT_LOCKED",
            );
            return Ok(true);
        }

        Ok(false)
    }
}

fn is_locked(user: &UserRecord, now: OffsetDateTime) -> bool {
    user.locked_until.is_some_and(|until| until > now)
}

fn generate_opaque_token() -> SecretString {
    let mut bytes = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut bytes[..]);
    let encoded = Zeroizing::new(hex::encode(&bytes[..]));
    SecretString::from(encoded.as_str())
}

/// Normalizes (`trim().to_ascii_lowercase()`) and validates an email address.
pub fn normalize_and_validate_email(raw: &str) -> Result<String, AppError> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > MAX_EMAIL_LEN {
        return Err(AppError::validation("Correo electrónico inválido"));
    }
    if normalized
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(AppError::validation("Correo electrónico inválido"));
    }

    let mut parts = normalized.split('@');
    let Some(local) = parts.next() else {
        return Err(AppError::validation("Correo electrónico inválido"));
    };
    let Some(domain) = parts.next() else {
        return Err(AppError::validation("Correo electrónico inválido"));
    };
    if parts.next().is_some() {
        return Err(AppError::validation("Correo electrónico inválido"));
    }

    if local.is_empty()
        || local.len() > 64
        || domain.len() < 3
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
        || domain.contains("..")
    {
        return Err(AppError::validation("Correo electrónico inválido"));
    }

    Ok(normalized)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn validates_and_normalizes_emails() {
        assert_eq!(
            normalize_and_validate_email("  Alice@Example.COM ").unwrap(),
            "alice@example.com"
        );
        assert!(normalize_and_validate_email("").is_err());
        assert!(normalize_and_validate_email("not-an-email").is_err());
        assert!(normalize_and_validate_email("a@b").is_err());
        assert!(normalize_and_validate_email("a@b..com").is_err());
        assert!(normalize_and_validate_email("a b@example.com").is_err());
    }

    #[tokio::test]
    async fn dummy_argon2_hash_is_valid_and_returns_false() {
        let res = verify_password(
            SecretString::from("AnyPassword#2026"),
            SecretString::from(DUMMY_ARGON2_PHC_HASH),
        )
        .await
        .unwrap();
        assert!(!res);
    }
}
