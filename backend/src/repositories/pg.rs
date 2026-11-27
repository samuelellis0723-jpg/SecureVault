//! PostgreSQL (`sqlx`) repository implementation aligned with `0001_initial_schema.sql`.
//!
//! All SQL statements use positional parameters (`$1, $2, ...`) with zero string interpolation,
//! bounded pool sizing, and strict `WHERE id = $1 AND user_id = $2` isolation on `notes`.

use std::str::FromStr;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use sqlx::{
    FromRow, PgPool, Row,
    postgres::{PgConnectOptions, PgPoolOptions, PgRow, PgSslMode},
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::{
    error::AppError,
    models::{
        AuthAttemptRecord, EncryptedNoteRecord, NoteCategory, RecoveryCodeRecord, SessionRecord,
        UserRecord,
    },
};
use crate::repositories::{
    AuthAttemptRepository, NoteRepository, RepoFuture, SessionRepository, UserRepository,
};

/// Maximum number of concurrent PostgreSQL connections in the application pool.
pub const PG_MAX_CONNECTIONS: u32 = 10;

/// Maximum time to wait for a pooled connection before failing fast.
pub const PG_ACQUIRE_TIMEOUT_SECS: u64 = 3;

/// PostgreSQL unique violation SQLSTATE (`23505`).
const PG_UNIQUE_VIOLATION: &str = "23505";

/// PostgreSQL-backed store implementing all repository traits.
#[derive(Clone)]
pub struct PgStore {
    pool: PgPool,
}

impl PgStore {
    /// Connects to PostgreSQL using `DATABASE_URL`, respecting `sslmode` (and enforcing
    /// `sslmode=verify-full` when `require_verify_full` is `true`).
    pub async fn connect(
        database_url: &SecretString,
        require_verify_full: bool,
    ) -> Result<Self, AppError> {
        let mut options = PgConnectOptions::from_str(database_url.expose_secret())
            .map_err(|_| AppError::Internal("invalid PostgreSQL connection options".to_owned()))?;

        if require_verify_full {
            options = options.ssl_mode(PgSslMode::VerifyFull);
        }

        let pool = PgPoolOptions::new()
            .max_connections(PG_MAX_CONNECTIONS)
            .acquire_timeout(Duration::from_secs(PG_ACQUIRE_TIMEOUT_SECS))
            .connect_with(options)
            .await
            .map_err(|err| AppError::Internal(format!("database connection failed: {err}")))?;

        Ok(Self { pool })
    }

    /// Wraps an already initialized [`PgPool`].
    #[must_use]
    pub const fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Exposes a reference to the underlying [`PgPool`].
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }
}

struct UserRow {
    id: Uuid,
    email: String,
    password_hash: String,
    totp_secret_ciphertext: Vec<u8>,
    totp_secret_nonce: Vec<u8>,
    totp_key_version: i16,
    totp_enabled: bool,
    failed_login_attempts: i16,
    locked_until: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl<'r> FromRow<'r, PgRow> for UserRow {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            email: row.try_get("email")?,
            password_hash: row.try_get("password_hash")?,
            totp_secret_ciphertext: row.try_get("totp_secret_ciphertext")?,
            totp_secret_nonce: row.try_get("totp_secret_nonce")?,
            totp_key_version: row.try_get("totp_key_version")?,
            totp_enabled: row.try_get("totp_enabled")?,
            failed_login_attempts: row.try_get("failed_login_attempts")?,
            locked_until: row.try_get("locked_until")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

impl From<UserRow> for UserRecord {
    fn from(row: UserRow) -> Self {
        Self {
            id: row.id,
            email: row.email,
            password_hash: SecretString::from(row.password_hash),
            totp_secret_ciphertext: row.totp_secret_ciphertext,
            totp_secret_nonce: row.totp_secret_nonce,
            totp_key_version: row.totp_key_version,
            totp_enabled: row.totp_enabled,
            failed_login_attempts: row.failed_login_attempts,
            locked_until: row.locked_until,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

struct SessionRow {
    id: Uuid,
    user_id: Uuid,
    token_hash: Vec<u8>,
    csrf_token_hash: Vec<u8>,
    mfa_verified: bool,
    last_seen_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    revoked_at: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
}

impl<'r> FromRow<'r, PgRow> for SessionRow {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            user_id: row.try_get("user_id")?,
            token_hash: row.try_get("token_hash")?,
            csrf_token_hash: row.try_get("csrf_token_hash")?,
            mfa_verified: row.try_get("mfa_verified")?,
            last_seen_at: row.try_get("last_seen_at")?,
            expires_at: row.try_get("expires_at")?,
            revoked_at: row.try_get("revoked_at")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

impl TryFrom<SessionRow> for SessionRecord {
    type Error = AppError;

    fn try_from(row: SessionRow) -> Result<Self, Self::Error> {
        let token_hash: [u8; 32] = row
            .token_hash
            .try_into()
            .map_err(|_| AppError::Internal("invalid session token_hash length".to_owned()))?;
        let csrf_token_hash: [u8; 32] = row
            .csrf_token_hash
            .try_into()
            .map_err(|_| AppError::Internal("invalid session csrf_token_hash length".to_owned()))?;

        Ok(Self {
            id: row.id,
            user_id: row.user_id,
            token_hash,
            csrf_token_hash,
            mfa_verified: row.mfa_verified,
            last_seen_at: row.last_seen_at,
            expires_at: row.expires_at,
            revoked_at: row.revoked_at,
            created_at: row.created_at,
        })
    }
}

struct NoteRow {
    id: Uuid,
    user_id: Uuid,
    category: String,
    title_ciphertext: Vec<u8>,
    title_nonce: Vec<u8>,
    content_ciphertext: Vec<u8>,
    content_nonce: Vec<u8>,
    key_version: i16,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl<'r> FromRow<'r, PgRow> for NoteRow {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            user_id: row.try_get("user_id")?,
            category: row.try_get("category")?,
            title_ciphertext: row.try_get("title_ciphertext")?,
            title_nonce: row.try_get("title_nonce")?,
            content_ciphertext: row.try_get("content_ciphertext")?,
            content_nonce: row.try_get("content_nonce")?,
            key_version: row.try_get("key_version")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

impl TryFrom<NoteRow> for EncryptedNoteRecord {
    type Error = AppError;

    fn try_from(row: NoteRow) -> Result<Self, Self::Error> {
        let category = NoteCategory::from_str(&row.category)
            .map_err(|_| AppError::Internal("invalid stored note category".to_owned()))?;

        Ok(Self {
            id: row.id,
            user_id: row.user_id,
            category,
            title_ciphertext: row.title_ciphertext,
            title_nonce: row.title_nonce,
            content_ciphertext: row.content_ciphertext,
            content_nonce: row.content_nonce,
            key_version: row.key_version,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

fn map_sqlx_error(err: &sqlx::Error) -> AppError {
    if let sqlx::Error::Database(db_err) = err
        && db_err.code().as_deref() == Some(PG_UNIQUE_VIOLATION)
    {
        return AppError::conflict(
            "EMAIL_ALREADY_EXISTS",
            "Ya existe una cuenta registrada con ese correo",
        );
    }
    AppError::Internal(format!("database query failed: {err}"))
}

impl UserRepository for PgStore {
    fn create_user(&self, user: UserRecord) -> RepoFuture<'_, UserRecord> {
        Box::pin(async move {
            let row = sqlx::query_as::<_, UserRow>(
                "INSERT INTO users (
                    id, email, password_hash, totp_secret_ciphertext, totp_secret_nonce,
                    totp_key_version, totp_enabled, failed_login_attempts, locked_until,
                    created_at, updated_at
                 )
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                 RETURNING id, email, password_hash, totp_secret_ciphertext, totp_secret_nonce,
                           totp_key_version, totp_enabled, failed_login_attempts, locked_until,
                           created_at, updated_at",
            )
            .bind(user.id)
            .bind(&user.email)
            .bind(user.password_hash.expose_secret())
            .bind(&user.totp_secret_ciphertext)
            .bind(&user.totp_secret_nonce)
            .bind(user.totp_key_version)
            .bind(user.totp_enabled)
            .bind(user.failed_login_attempts)
            .bind(user.locked_until)
            .bind(user.created_at)
            .bind(user.updated_at)
            .fetch_one(&self.pool)
            .await
            .map_err(|err| map_sqlx_error(&err))?;

            Ok(UserRecord::from(row))
        })
    }

    fn find_user_by_email<'a>(
        &'a self,
        email_lower: &'a str,
    ) -> RepoFuture<'a, Option<UserRecord>> {
        Box::pin(async move {
            let row = sqlx::query_as::<_, UserRow>(
                "SELECT id, email, password_hash, totp_secret_ciphertext, totp_secret_nonce,
                        totp_key_version, totp_enabled, failed_login_attempts, locked_until,
                        created_at, updated_at
                 FROM users
                 WHERE LOWER(email) = LOWER($1)",
            )
            .bind(email_lower)
            .fetch_optional(&self.pool)
            .await
            .map_err(|err| AppError::Internal(format!("find_user_by_email failed: {err}")))?;

            Ok(row.map(UserRecord::from))
        })
    }

    fn find_user_by_id(&self, user_id: Uuid) -> RepoFuture<'_, Option<UserRecord>> {
        Box::pin(async move {
            let row = sqlx::query_as::<_, UserRow>(
                "SELECT id, email, password_hash, totp_secret_ciphertext, totp_secret_nonce,
                        totp_key_version, totp_enabled, failed_login_attempts, locked_until,
                        created_at, updated_at
                 FROM users
                 WHERE id = $1",
            )
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|err| AppError::Internal(format!("find_user_by_id failed: {err}")))?;

            Ok(row.map(UserRecord::from))
        })
    }

    fn enable_totp_and_store_recovery_codes(
        &self,
        user_id: Uuid,
        recovery_codes: Vec<RecoveryCodeRecord>,
    ) -> RepoFuture<'_, UserRecord> {
        Box::pin(async move {
            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|err| AppError::Internal(format!("begin tx failed: {err}")))?;

            let row = sqlx::query_as::<_, UserRow>(
                "UPDATE users
                 SET totp_enabled = TRUE,
                     failed_login_attempts = 0,
                     locked_until = NULL,
                     updated_at = NOW()
                 WHERE id = $1
                 RETURNING id, email, password_hash, totp_secret_ciphertext, totp_secret_nonce,
                           totp_key_version, totp_enabled, failed_login_attempts, locked_until,
                           created_at, updated_at",
            )
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|err| AppError::Internal(format!("enable_totp failed: {err}")))?
            .ok_or_else(|| AppError::Unauthorized("Usuario no encontrado".to_owned()))?;

            sqlx::query("DELETE FROM totp_recovery_codes WHERE user_id = $1")
                .bind(user_id)
                .execute(&mut *tx)
                .await
                .map_err(|err| {
                    AppError::Internal(format!("clear old recovery codes failed: {err}"))
                })?;

            for code in recovery_codes {
                sqlx::query(
                    "INSERT INTO totp_recovery_codes (id, user_id, code_hash, used_at, created_at)
                     VALUES ($1, $2, $3, $4, $5)",
                )
                .bind(code.id)
                .bind(code.user_id)
                .bind(&code.code_hash[..])
                .bind(code.used_at)
                .bind(code.created_at)
                .execute(&mut *tx)
                .await
                .map_err(|err| AppError::Internal(format!("insert recovery code failed: {err}")))?;
            }

            tx.commit()
                .await
                .map_err(|err| AppError::Internal(format!("commit tx failed: {err}")))?;

            Ok(UserRecord::from(row))
        })
    }

    fn consume_recovery_code(
        &self,
        user_id: Uuid,
        code_hash: [u8; 32],
        now: OffsetDateTime,
    ) -> RepoFuture<'_, bool> {
        Box::pin(async move {
            let result = sqlx::query(
                "UPDATE totp_recovery_codes
                 SET used_at = $3
                 WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL",
            )
            .bind(user_id)
            .bind(&code_hash[..])
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|err| AppError::Internal(format!("consume_recovery_code failed: {err}")))?;

            Ok(result.rows_affected() > 0)
        })
    }

    fn update_login_failure(
        &self,
        user_id: Uuid,
        failed_attempts: i16,
        locked_until: Option<OffsetDateTime>,
    ) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "UPDATE users
                 SET failed_login_attempts = $2,
                     locked_until = $3,
                     updated_at = NOW()
                 WHERE id = $1",
            )
            .bind(user_id)
            .bind(failed_attempts)
            .bind(locked_until)
            .execute(&self.pool)
            .await
            .map_err(|err| AppError::Internal(format!("update_login_failure failed: {err}")))?;

            Ok(())
        })
    }

    fn reset_login_failures(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "UPDATE users
                 SET failed_login_attempts = 0,
                     locked_until = NULL,
                     updated_at = NOW()
                 WHERE id = $1",
            )
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|err| AppError::Internal(format!("reset_login_failures failed: {err}")))?;

            Ok(())
        })
    }

    fn list_users_with_totp_version_ne(
        &self,
        active_version: i16,
        limit: i64,
    ) -> RepoFuture<'_, Vec<UserRecord>> {
        Box::pin(async move {
            let rows = sqlx::query_as::<_, UserRow>(
                "SELECT id, email, password_hash, totp_secret_ciphertext, totp_secret_nonce,
                        totp_key_version, totp_enabled, failed_login_attempts, locked_until,
                        created_at, updated_at
                 FROM users
                 WHERE totp_key_version != $1
                 ORDER BY id ASC
                 LIMIT $2",
            )
            .bind(active_version)
            .bind(limit.max(0))
            .fetch_all(&self.pool)
            .await
            .map_err(|err| {
                AppError::Internal(format!("list_users_with_totp_version_ne failed: {err}"))
            })?;

            Ok(rows.into_iter().map(UserRecord::from).collect())
        })
    }

    fn update_user_totp_secret(
        &self,
        user_id: Uuid,
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        key_version: i16,
    ) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "UPDATE users
                 SET totp_secret_ciphertext = $2,
                     totp_secret_nonce = $3,
                     totp_key_version = $4,
                     updated_at = NOW()
                 WHERE id = $1",
            )
            .bind(user_id)
            .bind(&ciphertext)
            .bind(&nonce)
            .bind(key_version)
            .execute(&self.pool)
            .await
            .map_err(|err| AppError::Internal(format!("update_user_totp_secret failed: {err}")))?;

            Ok(())
        })
    }
}

impl SessionRepository for PgStore {
    fn create_session(&self, session: SessionRecord) -> RepoFuture<'_, SessionRecord> {
        Box::pin(async move {
            let row = sqlx::query_as::<_, SessionRow>(
                "INSERT INTO sessions (
                    id, user_id, token_hash, csrf_token_hash, mfa_verified,
                    last_seen_at, expires_at, revoked_at, created_at
                 )
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                 RETURNING id, user_id, token_hash, csrf_token_hash, mfa_verified,
                           last_seen_at, expires_at, revoked_at, created_at",
            )
            .bind(session.id)
            .bind(session.user_id)
            .bind(&session.token_hash[..])
            .bind(&session.csrf_token_hash[..])
            .bind(session.mfa_verified)
            .bind(session.last_seen_at)
            .bind(session.expires_at)
            .bind(session.revoked_at)
            .bind(session.created_at)
            .fetch_one(&self.pool)
            .await
            .map_err(|err| AppError::Internal(format!("create_session failed: {err}")))?;

            SessionRecord::try_from(row)
        })
    }

    fn find_session_by_token_hash(
        &self,
        token_hash: [u8; 32],
    ) -> RepoFuture<'_, Option<SessionRecord>> {
        Box::pin(async move {
            let row = sqlx::query_as::<_, SessionRow>(
                "SELECT id, user_id, token_hash, csrf_token_hash, mfa_verified,
                        last_seen_at, expires_at, revoked_at, created_at
                 FROM sessions
                 WHERE token_hash = $1",
            )
            .bind(&token_hash[..])
            .fetch_optional(&self.pool)
            .await
            .map_err(|err| {
                AppError::Internal(format!("find_session_by_token_hash failed: {err}"))
            })?;

            row.map(SessionRecord::try_from).transpose()
        })
    }

    fn touch_session(&self, session_id: Uuid, last_seen_at: OffsetDateTime) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "UPDATE sessions
                 SET last_seen_at = $2
                 WHERE id = $1",
            )
            .bind(session_id)
            .bind(last_seen_at)
            .execute(&self.pool)
            .await
            .map_err(|err| AppError::Internal(format!("touch_session failed: {err}")))?;

            Ok(())
        })
    }

    fn revoke_session(&self, session_id: Uuid, revoked_at: OffsetDateTime) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "UPDATE sessions
                 SET revoked_at = $2
                 WHERE id = $1",
            )
            .bind(session_id)
            .bind(revoked_at)
            .execute(&self.pool)
            .await
            .map_err(|err| AppError::Internal(format!("revoke_session failed: {err}")))?;

            Ok(())
        })
    }

    fn revoke_all_user_sessions(
        &self,
        user_id: Uuid,
        revoked_at: OffsetDateTime,
    ) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "UPDATE sessions
                 SET revoked_at = $2
                 WHERE user_id = $1 AND revoked_at IS NULL",
            )
            .bind(user_id)
            .bind(revoked_at)
            .execute(&self.pool)
            .await
            .map_err(|err| AppError::Internal(format!("revoke_all_user_sessions failed: {err}")))?;

            Ok(())
        })
    }
}

impl NoteRepository for PgStore {
    fn create_note(&self, note: EncryptedNoteRecord) -> RepoFuture<'_, EncryptedNoteRecord> {
        Box::pin(async move {
            let row = sqlx::query_as::<_, NoteRow>(
                "INSERT INTO notes (
                    id, user_id, category, title_ciphertext, title_nonce,
                    content_ciphertext, content_nonce, key_version, created_at, updated_at
                 )
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                 RETURNING id, user_id, category, title_ciphertext, title_nonce,
                           content_ciphertext, content_nonce, key_version, created_at, updated_at",
            )
            .bind(note.id)
            .bind(note.user_id)
            .bind(note.category.as_str())
            .bind(&note.title_ciphertext)
            .bind(&note.title_nonce)
            .bind(&note.content_ciphertext)
            .bind(&note.content_nonce)
            .bind(note.key_version)
            .bind(note.created_at)
            .bind(note.updated_at)
            .fetch_one(&self.pool)
            .await
            .map_err(|err| AppError::Internal(format!("create_note failed: {err}")))?;

            EncryptedNoteRecord::try_from(row)
        })
    }

    fn list_notes(
        &self,
        user_id: Uuid,
        category: Option<NoteCategory>,
        page: u32,
        limit: u32,
    ) -> RepoFuture<'_, (Vec<EncryptedNoteRecord>, u64)> {
        Box::pin(async move {
            let safe_page = i64::from(page.max(1));
            let safe_limit = i64::from(limit.max(1));
            let offset = safe_page.saturating_sub(1).saturating_mul(safe_limit);

            let (rows, total): (Vec<NoteRow>, i64) = if let Some(cat) = category {
                let total_count: (i64,) = sqlx::query_as(
                    "SELECT COUNT(*) FROM notes WHERE user_id = $1 AND category = $2",
                )
                .bind(user_id)
                .bind(cat.as_str())
                .fetch_one(&self.pool)
                .await
                .map_err(|err| AppError::Internal(format!("count notes failed: {err}")))?;

                let rows = sqlx::query_as::<_, NoteRow>(
                    "SELECT id, user_id, category, title_ciphertext, title_nonce,
                            content_ciphertext, content_nonce, key_version, created_at, updated_at
                     FROM notes
                     WHERE user_id = $1 AND category = $2
                     ORDER BY created_at DESC, id DESC
                     LIMIT $3 OFFSET $4",
                )
                .bind(user_id)
                .bind(cat.as_str())
                .bind(safe_limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await
                .map_err(|err| AppError::Internal(format!("list notes failed: {err}")))?;

                (rows, total_count.0)
            } else {
                let total_count: (i64,) =
                    sqlx::query_as("SELECT COUNT(*) FROM notes WHERE user_id = $1")
                        .bind(user_id)
                        .fetch_one(&self.pool)
                        .await
                        .map_err(|err| AppError::Internal(format!("count notes failed: {err}")))?;

                let rows = sqlx::query_as::<_, NoteRow>(
                    "SELECT id, user_id, category, title_ciphertext, title_nonce,
                            content_ciphertext, content_nonce, key_version, created_at, updated_at
                     FROM notes
                     WHERE user_id = $1
                     ORDER BY created_at DESC, id DESC
                     LIMIT $2 OFFSET $3",
                )
                .bind(user_id)
                .bind(safe_limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await
                .map_err(|err| AppError::Internal(format!("list notes failed: {err}")))?;

                (rows, total_count.0)
            };

            let mut notes = Vec::with_capacity(rows.len());
            for row in rows {
                notes.push(EncryptedNoteRecord::try_from(row)?);
            }
            let total_u64 = u64::try_from(total.max(0)).unwrap_or(0);
            Ok((notes, total_u64))
        })
    }

    fn find_note_by_id(
        &self,
        note_id: Uuid,
        user_id: Uuid,
    ) -> RepoFuture<'_, Option<EncryptedNoteRecord>> {
        Box::pin(async move {
            let row = sqlx::query_as::<_, NoteRow>(
                "SELECT id, user_id, category, title_ciphertext, title_nonce,
                        content_ciphertext, content_nonce, key_version, created_at, updated_at
                 FROM notes
                 WHERE id = $1 AND user_id = $2",
            )
            .bind(note_id)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|err| AppError::Internal(format!("find_note_by_id failed: {err}")))?;

            row.map(EncryptedNoteRecord::try_from).transpose()
        })
    }

    fn update_note(
        &self,
        note: EncryptedNoteRecord,
    ) -> RepoFuture<'_, Option<EncryptedNoteRecord>> {
        Box::pin(async move {
            let row = sqlx::query_as::<_, NoteRow>(
                "UPDATE notes
                 SET category = $3,
                     title_ciphertext = $4,
                     title_nonce = $5,
                     content_ciphertext = $6,
                     content_nonce = $7,
                     key_version = $8,
                     updated_at = NOW()
                 WHERE id = $1 AND user_id = $2
                 RETURNING id, user_id, category, title_ciphertext, title_nonce,
                           content_ciphertext, content_nonce, key_version, created_at, updated_at",
            )
            .bind(note.id)
            .bind(note.user_id)
            .bind(note.category.as_str())
            .bind(&note.title_ciphertext)
            .bind(&note.title_nonce)
            .bind(&note.content_ciphertext)
            .bind(&note.content_nonce)
            .bind(note.key_version)
            .fetch_optional(&self.pool)
            .await
            .map_err(|err| AppError::Internal(format!("update_note failed: {err}")))?;

            row.map(EncryptedNoteRecord::try_from).transpose()
        })
    }

    fn delete_note(&self, note_id: Uuid, user_id: Uuid) -> RepoFuture<'_, bool> {
        Box::pin(async move {
            let result = sqlx::query("DELETE FROM notes WHERE id = $1 AND user_id = $2")
                .bind(note_id)
                .bind(user_id)
                .execute(&self.pool)
                .await
                .map_err(|err| AppError::Internal(format!("delete_note failed: {err}")))?;

            Ok(result.rows_affected() > 0)
        })
    }

    fn list_notes_with_key_version_ne(
        &self,
        active_version: i16,
        limit: i64,
    ) -> RepoFuture<'_, Vec<EncryptedNoteRecord>> {
        Box::pin(async move {
            let rows = sqlx::query_as::<_, NoteRow>(
                "SELECT id, user_id, category, title_ciphertext, title_nonce,
                        content_ciphertext, content_nonce, key_version, created_at, updated_at
                 FROM notes
                 WHERE key_version != $1
                 ORDER BY id ASC
                 LIMIT $2",
            )
            .bind(active_version)
            .bind(limit.max(0))
            .fetch_all(&self.pool)
            .await
            .map_err(|err| {
                AppError::Internal(format!("list_notes_with_key_version_ne failed: {err}"))
            })?;

            let mut notes = Vec::with_capacity(rows.len());
            for row in rows {
                notes.push(EncryptedNoteRecord::try_from(row)?);
            }
            Ok(notes)
        })
    }

    fn update_note_encryption(
        &self,
        note_id: Uuid,
        user_id: Uuid,
        title_ciphertext: Vec<u8>,
        title_nonce: Vec<u8>,
        content_ciphertext: Vec<u8>,
        content_nonce: Vec<u8>,
        key_version: i16,
    ) -> RepoFuture<'_, bool> {
        Box::pin(async move {
            let result = sqlx::query(
                "UPDATE notes
                 SET title_ciphertext = $3,
                     title_nonce = $4,
                     content_ciphertext = $5,
                     content_nonce = $6,
                     key_version = $7,
                     updated_at = NOW()
                 WHERE id = $1 AND user_id = $2",
            )
            .bind(note_id)
            .bind(user_id)
            .bind(&title_ciphertext)
            .bind(&title_nonce)
            .bind(&content_ciphertext)
            .bind(&content_nonce)
            .bind(key_version)
            .execute(&self.pool)
            .await
            .map_err(|err| AppError::Internal(format!("update_note_encryption failed: {err}")))?;

            Ok(result.rows_affected() > 0)
        })
    }
}

impl AuthAttemptRepository for PgStore {
    fn record_attempt(&self, attempt: AuthAttemptRecord) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO auth_attempts (
                    id, identifier_hash, ip_hash, attempt_type, succeeded, created_at
                 )
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(attempt.id)
            .bind(&attempt.identifier_hash[..])
            .bind(&attempt.ip_hash[..])
            .bind(attempt.attempt_type.as_str())
            .bind(attempt.succeeded)
            .bind(attempt.created_at)
            .execute(&self.pool)
            .await
            .map_err(|err| AppError::Internal(format!("record_attempt failed: {err}")))?;

            Ok(())
        })
    }

    fn count_recent_failures(
        &self,
        identifier_hash: [u8; 32],
        since: OffsetDateTime,
    ) -> RepoFuture<'_, u64> {
        Box::pin(async move {
            let count: (i64,) = sqlx::query_as(
                "SELECT COUNT(*)
                 FROM auth_attempts
                 WHERE identifier_hash = $1 AND succeeded = FALSE AND created_at >= $2",
            )
            .bind(&identifier_hash[..])
            .bind(since)
            .fetch_one(&self.pool)
            .await
            .map_err(|err| AppError::Internal(format!("count_recent_failures failed: {err}")))?;

            Ok(u64::try_from(count.0.max(0)).unwrap_or(0))
        })
    }
}
