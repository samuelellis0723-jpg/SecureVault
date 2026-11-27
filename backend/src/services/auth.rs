//! Authentication, mandatory TOTP MFA, session rotation, CSRF, and brute-force lockout service.

use rand::{RngCore, rngs::OsRng};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use subtle::ConstantTimeEq;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{
    CryptoError,
    cipher::{AAD_ENTITY_TOTP_SECRET, KeyRing},
    password::{hash_password, validate_password, verify_password},
    totp::{
        TOTP_DIGITS, TOTP_SECRET_LEN, build_totp_enrollment, generate_recovery_codes,
        generate_totp_secret, hash_recovery_code_bytes, keyed_sha256_bytes, keyed_sha256_hex,
        normalize_recovery_code, sha256_bytes, verify_totp_now,
    },
};
use crate::domain::{
    error::AppError,
    models::{
        AuthAttemptRecord, AuthAttemptType, RecoveryCodeRecord, SessionRecord, UserPublic,
        UserRecord,
    },
};
use crate::repositories::VaultRepositories;
use crate::services::alerts::{AlertEventKind, AlertService};

/// Pre-MFA session lifetime (5 minutes).
pub const PRE_MFA_SESSION_TTL_SECS: i64 = 5 * 60;

/// Full MFA-verified session absolute lifetime (8 hours).
pub const FULL_SESSION_TTL_SECS: i64 = 8 * 60 * 60;

/// Full MFA-verified session inactivity timeout (30 minutes).
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

/// TOTP setup payload returned during registration or incomplete enrollment login.
#[derive(Debug, Clone, Serialize)]
pub struct TotpSetupDto {
    pub otpauth_uri: String,
    pub secret_base32: String,
    pub qr_svg: String,
}

/// Output of `POST /api/v1/auth/register`.
pub struct RegisterOutput {
    pub session_token: SecretString,
    pub session_max_age_secs: i64,
    pub csrf_token: String,
    pub totp: TotpSetupDto,
}

/// Output of `POST /api/v1/auth/totp/confirm`.
pub struct ConfirmTotpOutput {
    pub user: UserPublic,
    pub session_token: SecretString,
    pub session_max_age_secs: i64,
    pub csrf_token: String,
    pub recovery_codes: Vec<String>,
}

/// Output of `POST /api/v1/auth/login`.
pub struct LoginOutput {
    pub mfa_required: bool,
    pub totp_enrolled: bool,
    pub csrf_token: String,
    pub totp: Option<TotpSetupDto>,
    pub session_token: SecretString,
    pub session_max_age_secs: i64,
}

/// Output of `POST /api/v1/auth/totp/verify`.
pub struct VerifyTotpOutput {
    pub user: UserPublic,
    pub session_token: SecretString,
    pub session_max_age_secs: i64,
    pub csrf_token: String,
}

/// Output of `GET /api/v1/auth/me`.
#[derive(Debug, Clone, Serialize)]
pub struct MeOutput {
    pub authenticated: bool,
    pub mfa_verified: bool,
    pub user: UserPublic,
    pub csrf_token: String,
}

/// Core authentication and MFA service.
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

    /// Registers a new user (when `ALLOW_REGISTRATION=true`), encrypts their TOTP secret,
    /// and opens a 5-minute pre-MFA session.
    pub async fn register(
        &self,
        email: &str,
        password: SecretString,
    ) -> Result<RegisterOutput, AppError> {
        if !self.allow_registration {
            return Err(AppError::RegistrationDisabled);
        }

        let normalized_email = normalize_and_validate_email(email)?;
        validate_password(password.expose_secret())?;

        let password_hash = hash_password(password).await?;
        let user_id = Uuid::new_v4();
        let raw_totp_secret = generate_totp_secret();
        let enrollment = build_totp_enrollment(&normalized_email, raw_totp_secret)?;

        let encrypted_totp = self.key_ring.encrypt(
            &enrollment.raw_secret[..],
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
            .issue_session(created.id, false, PRE_MFA_SESSION_TTL_SECS)
            .await?;

        Ok(RegisterOutput {
            session_token,
            session_max_age_secs: PRE_MFA_SESSION_TTL_SECS,
            csrf_token,
            totp: TotpSetupDto {
                otpauth_uri: enrollment.otpauth_uri.expose_secret().to_owned(),
                secret_base32: enrollment.secret_base32.expose_secret().to_owned(),
                qr_svg: enrollment.qr_svg,
            },
        })
    }

    /// Confirms initial TOTP enrollment, enables MFA, rotates session to `mfa_verified = true`,
    /// and returns 8 single-use recovery codes once.
    pub async fn confirm_totp(
        &self,
        auth_session: &AuthenticatedSession,
        code: &str,
        client_ip: &str,
        request_id: &str,
    ) -> Result<ConfirmTotpOutput, AppError> {
        let trimmed_code = validate_totp_code_format(code)?;

        let user = self
            .repos
            .users
            .find_user_by_id(auth_session.session.user_id)
            .await?
            .ok_or_else(|| AppError::Unauthorized("Sesión no válida".to_owned()))?;

        if user.totp_enabled {
            return Err(AppError::conflict(
                "TOTP_ALREADY_ENABLED",
                "El segundo factor TOTP ya está activado para esta cuenta",
            ));
        }

        let now = OffsetDateTime::now_utc();
        if is_locked(&user, now) {
            return Err(AppError::AccountLocked);
        }

        let totp_secret = self.decrypt_user_totp_secret(&user, client_ip, request_id)?;
        let valid = verify_totp_now(&totp_secret[..], trimmed_code)?;

        let identifier_hash = self.hash_identifier(&user.email)?;
        let ip_hash = self.hash_ip(client_ip)?;
        self.repos
            .auth_attempts
            .record_attempt(AuthAttemptRecord {
                id: Uuid::new_v4(),
                identifier_hash,
                ip_hash,
                attempt_type: AuthAttemptType::Totp,
                succeeded: valid,
                created_at: now,
            })
            .await?;

        if !valid {
            let locked = self
                .record_failure_and_check_lockout(
                    Some(&user),
                    identifier_hash,
                    now,
                    client_ip,
                    request_id,
                )
                .await?;
            if locked {
                return Err(AppError::AccountLocked);
            }
            return Err(AppError::InvalidTotpCode);
        }

        let raw_recovery_codes = generate_recovery_codes();
        let mut recovery_records = Vec::with_capacity(raw_recovery_codes.len());
        let mut recovery_plain = Vec::with_capacity(raw_recovery_codes.len());

        for secret_code in raw_recovery_codes {
            let plain = secret_code.expose_secret().to_owned();
            let code_hash = hash_recovery_code_bytes(&plain, &self.pepper)?;
            recovery_records.push(RecoveryCodeRecord {
                id: Uuid::new_v4(),
                user_id: user.id,
                code_hash,
                used_at: None,
                created_at: now,
            });
            recovery_plain.push(plain);
        }

        let updated_user = self
            .repos
            .users
            .enable_totp_and_store_recovery_codes(user.id, recovery_records)
            .await?;

        // Rotate session to prevent session fixation: revoke pre-MFA session, issue full session.
        self.repos
            .sessions
            .revoke_session(auth_session.session.id, now)
            .await?;
        let (session_token, csrf_token) = self
            .issue_session(updated_user.id, true, FULL_SESSION_TTL_SECS)
            .await?;

        Ok(ConfirmTotpOutput {
            user: UserPublic::from(&updated_user),
            session_token,
            session_max_age_secs: FULL_SESSION_TTL_SECS,
            csrf_token,
            recovery_codes: recovery_plain,
        })
    }

    /// Verifies email + password (with Argon2id timing-attack mitigation for missing users),
    /// enforces brute-force lockout, and creates a 5-minute pre-MFA session.
    pub async fn login(
        &self,
        email: &str,
        password: SecretString,
        client_ip: &str,
        request_id: &str,
    ) -> Result<LoginOutput, AppError> {
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
            .issue_session(user.id, false, PRE_MFA_SESSION_TTL_SECS)
            .await?;

        let totp = if user.totp_enabled {
            None
        } else {
            let secret_vec = self.decrypt_user_totp_secret(&user, client_ip, request_id)?;
            let raw_arr: [u8; TOTP_SECRET_LEN] = secret_vec
                .as_slice()
                .try_into()
                .map_err(|_| AppError::CryptoIntegrity("invalid totp secret length".to_owned()))?;
            let enrollment = build_totp_enrollment(&user.email, Zeroizing::new(raw_arr))?;
            Some(TotpSetupDto {
                otpauth_uri: enrollment.otpauth_uri.expose_secret().to_owned(),
                secret_base32: enrollment.secret_base32.expose_secret().to_owned(),
                qr_svg: enrollment.qr_svg,
            })
        };

        Ok(LoginOutput {
            mfa_required: true,
            totp_enrolled: user.totp_enabled,
            csrf_token,
            totp,
            session_token,
            session_max_age_secs: PRE_MFA_SESSION_TTL_SECS,
        })
    }

    /// Completes second-factor authentication using either a 6-digit TOTP code or a single-use
    /// recovery code, rotating the session to `mfa_verified = true`.
    pub async fn verify_totp(
        &self,
        auth_session: &AuthenticatedSession,
        code: Option<&str>,
        recovery_code: Option<&str>,
        client_ip: &str,
        request_id: &str,
    ) -> Result<VerifyTotpOutput, AppError> {
        let mode = match (code, recovery_code) {
            (Some(c), None) => VerificationMode::Totp(validate_totp_code_format(c)?),
            (None, Some(r)) => {
                if normalize_recovery_code(r).is_none() {
                    return Err(AppError::validation(
                        "Formato de código de recuperación inválido",
                    ));
                }
                VerificationMode::Recovery(r)
            }
            _ => {
                return Err(AppError::validation(
                    "Debes enviar exactamente 'code' o 'recovery_code'",
                ));
            }
        };

        let user = self
            .repos
            .users
            .find_user_by_id(auth_session.session.user_id)
            .await?
            .ok_or_else(|| AppError::Unauthorized("Sesión no válida".to_owned()))?;

        if !user.totp_enabled {
            return Err(AppError::Forbidden(
                "Debes confirmar el enrolamiento TOTP antes de verificar".to_owned(),
            ));
        }

        let now = OffsetDateTime::now_utc();
        if is_locked(&user, now) {
            return Err(AppError::AccountLocked);
        }

        let identifier_hash = self.hash_identifier(&user.email)?;
        let ip_hash = self.hash_ip(client_ip)?;

        let (valid, attempt_type, invalid_err) = match mode {
            VerificationMode::Totp(trimmed_code) => {
                let secret = self.decrypt_user_totp_secret(&user, client_ip, request_id)?;
                let ok = verify_totp_now(&secret[..], trimmed_code)?;
                (ok, AuthAttemptType::Totp, AppError::InvalidTotpCode)
            }
            VerificationMode::Recovery(raw_recovery) => {
                let code_hash = hash_recovery_code_bytes(raw_recovery, &self.pepper)?;
                let consumed = self
                    .repos
                    .users
                    .consume_recovery_code(user.id, code_hash, now)
                    .await?;
                (
                    consumed,
                    AuthAttemptType::Recovery,
                    AppError::InvalidRecoveryCode,
                )
            }
        };

        self.repos
            .auth_attempts
            .record_attempt(AuthAttemptRecord {
                id: Uuid::new_v4(),
                identifier_hash,
                ip_hash,
                attempt_type,
                succeeded: valid,
                created_at: now,
            })
            .await?;

        if !valid {
            let locked = self
                .record_failure_and_check_lockout(
                    Some(&user),
                    identifier_hash,
                    now,
                    client_ip,
                    request_id,
                )
                .await?;
            if locked {
                return Err(AppError::AccountLocked);
            }
            return Err(invalid_err);
        }

        self.repos.users.reset_login_failures(user.id).await?;
        self.repos
            .sessions
            .revoke_session(auth_session.session.id, now)
            .await?;

        let (session_token, csrf_token) = self
            .issue_session(user.id, true, FULL_SESSION_TTL_SECS)
            .await?;

        Ok(VerifyTotpOutput {
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

    /// Resolves and validates a session from the opaque cookie token, enforcing absolute
    /// expiration, revocation, and 30-minute inactivity timeout for MFA-verified sessions.
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
        if session.revoked_at.is_some() || session.expires_at <= now {
            return Err(AppError::Unauthorized(
                "Sesión revocada o expirada".to_owned(),
            ));
        }

        if session.mfa_verified {
            let inactivity_deadline =
                session.last_seen_at + Duration::seconds(SESSION_INACTIVITY_TTL_SECS);
            if inactivity_deadline <= now {
                return Err(AppError::Unauthorized(
                    "Sesión expirada por inactividad".to_owned(),
                ));
            }
            self.repos.sessions.touch_session(session.id, now).await?;
        }

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
            mfa_verified: auth_session.session.mfa_verified,
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

    fn decrypt_user_totp_secret(
        &self,
        user: &UserRecord,
        client_ip: &str,
        request_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, AppError> {
        self.key_ring
            .decrypt_parts(
                &user.totp_secret_ciphertext,
                &user.totp_secret_nonce,
                user.totp_key_version,
                user.id,
                AAD_ENTITY_TOTP_SECRET,
                user.id,
            )
            .map_err(|err| {
                if matches!(
                    err,
                    CryptoError::IntegrityFailure
                        | CryptoError::KeyVersionNotFound(_)
                        | CryptoError::InvalidNonceLength
                ) {
                    self.alerts.notify(
                        AlertEventKind::CryptoIntegrityFailure,
                        request_id,
                        client_ip,
                        "INTERNAL_ERROR",
                    );
                }
                AppError::from(err)
            })
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

enum VerificationMode<'a> {
    Totp(&'a str),
    Recovery(&'a str),
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

fn validate_totp_code_format(raw: &str) -> Result<&str, AppError> {
    let trimmed = raw.trim();
    if trimmed.len() == TOTP_DIGITS && trimmed.bytes().all(|b| b.is_ascii_digit()) {
        Ok(trimmed)
    } else {
        Err(AppError::validation(
            "El código TOTP debe tener exactamente 6 dígitos numéricos",
        ))
    }
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
