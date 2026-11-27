//! Persistence repository traits and concrete storage backends (`memory` and `pg`).

pub mod memory;
pub mod pg;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::{
    error::AppError,
    models::{
        AuthAttemptRecord, EncryptedNoteRecord, NoteCategory, RecoveryCodeRecord, SessionRecord,
        UserRecord,
    },
};

/// Boxed `Send` future alias used by object-safe repository traits.
pub type RepoFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, AppError>> + Send + 'a>>;

/// Persistence operations for `users` and `totp_recovery_codes`.
pub trait UserRepository: Send + Sync {
    /// Persists a new user, failing with `409 EMAIL_ALREADY_EXISTS` on duplicate `LOWER(email)`.
    fn create_user(&self, user: UserRecord) -> RepoFuture<'_, UserRecord>;

    /// Finds a user by normalized lowercase email.
    fn find_user_by_email<'a>(&'a self, email_lower: &'a str)
    -> RepoFuture<'a, Option<UserRecord>>;

    /// Finds a user by UUID.
    fn find_user_by_id(&self, user_id: Uuid) -> RepoFuture<'_, Option<UserRecord>>;

    /// Activates `totp_enabled = true`, resets failure counters, and stores 8 hashed recovery codes.
    fn enable_totp_and_store_recovery_codes(
        &self,
        user_id: Uuid,
        recovery_codes: Vec<RecoveryCodeRecord>,
    ) -> RepoFuture<'_, UserRecord>;

    /// Atomically consumes a single-use recovery code (`used_at IS NULL -> used_at = now`).
    /// Returns `true` if a valid unused code was consumed.
    fn consume_recovery_code(
        &self,
        user_id: Uuid,
        code_hash: [u8; 32],
        now: OffsetDateTime,
    ) -> RepoFuture<'_, bool>;

    /// Updates `failed_login_attempts` and optional `locked_until`.
    fn update_login_failure(
        &self,
        user_id: Uuid,
        failed_attempts: i16,
        locked_until: Option<OffsetDateTime>,
    ) -> RepoFuture<'_, ()>;

    /// Resets `failed_login_attempts = 0` and `locked_until = NULL`.
    fn reset_login_failures(&self, user_id: Uuid) -> RepoFuture<'_, ()>;

    /// Lists up to `limit` users whose `totp_key_version != active_version` for key rotation.
    fn list_users_with_totp_version_ne(
        &self,
        active_version: i16,
        limit: i64,
    ) -> RepoFuture<'_, Vec<UserRecord>>;

    /// Updates a user's encrypted TOTP secret and key version during rotation.
    fn update_user_totp_secret(
        &self,
        user_id: Uuid,
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        key_version: i16,
    ) -> RepoFuture<'_, ()>;
}

/// Persistence operations for `sessions`.
pub trait SessionRepository: Send + Sync {
    /// Creates a new server-side opaque session.
    fn create_session(&self, session: SessionRecord) -> RepoFuture<'_, SessionRecord>;

    /// Looks up a session by the SHA-256 hash of its opaque cookie token.
    fn find_session_by_token_hash(
        &self,
        token_hash: [u8; 32],
    ) -> RepoFuture<'_, Option<SessionRecord>>;

    /// Updates `last_seen_at` for an active session.
    fn touch_session(&self, session_id: Uuid, last_seen_at: OffsetDateTime) -> RepoFuture<'_, ()>;

    /// Revokes a single session by ID.
    fn revoke_session(&self, session_id: Uuid, revoked_at: OffsetDateTime) -> RepoFuture<'_, ()>;

    /// Revokes all active sessions belonging to `user_id`.
    fn revoke_all_user_sessions(
        &self,
        user_id: Uuid,
        revoked_at: OffsetDateTime,
    ) -> RepoFuture<'_, ()>;
}

/// Persistence operations for `notes` with strict `user_id` BOLA isolation.
pub trait NoteRepository: Send + Sync {
    /// Persists a newly encrypted note.
    fn create_note(&self, note: EncryptedNoteRecord) -> RepoFuture<'_, EncryptedNoteRecord>;

    /// Lists encrypted notes belonging to `user_id` ordered by `created_at DESC` with total count.
    fn list_notes(
        &self,
        user_id: Uuid,
        category: Option<NoteCategory>,
        page: u32,
        limit: u32,
    ) -> RepoFuture<'_, (Vec<EncryptedNoteRecord>, u64)>;

    /// Finds a single note owned by `user_id` (`WHERE id = $1 AND user_id = $2`).
    fn find_note_by_id(
        &self,
        note_id: Uuid,
        user_id: Uuid,
    ) -> RepoFuture<'_, Option<EncryptedNoteRecord>>;

    /// Updates an encrypted note owned by `user_id` (`WHERE id = $1 AND user_id = $2`).
    fn update_note(&self, note: EncryptedNoteRecord)
    -> RepoFuture<'_, Option<EncryptedNoteRecord>>;

    /// Deletes a note owned by `user_id` (`WHERE id = $1 AND user_id = $2`).
    fn delete_note(&self, note_id: Uuid, user_id: Uuid) -> RepoFuture<'_, bool>;

    /// Lists up to `limit` notes whose `key_version != active_version` for key rotation.
    fn list_notes_with_key_version_ne(
        &self,
        active_version: i16,
        limit: i64,
    ) -> RepoFuture<'_, Vec<EncryptedNoteRecord>>;

    /// Updates re-encrypted title/content blobs and `key_version` for a note during rotation.
    #[allow(clippy::too_many_arguments)]
    fn update_note_encryption(
        &self,
        note_id: Uuid,
        user_id: Uuid,
        title_ciphertext: Vec<u8>,
        title_nonce: Vec<u8>,
        content_ciphertext: Vec<u8>,
        content_nonce: Vec<u8>,
        key_version: i16,
    ) -> RepoFuture<'_, bool>;
}

/// Persistence operations for `auth_attempts`.
pub trait AuthAttemptRepository: Send + Sync {
    /// Records an authentication attempt (hashed identifier and IP only).
    fn record_attempt(&self, attempt: AuthAttemptRecord) -> RepoFuture<'_, ()>;

    /// Counts failed attempts for `identifier_hash` since `since` (UTC).
    fn count_recent_failures(
        &self,
        identifier_hash: [u8; 32],
        since: OffsetDateTime,
    ) -> RepoFuture<'_, u64>;
}

/// Bundled repository handles shared across application services.
#[derive(Clone)]
pub struct VaultRepositories {
    pub users: Arc<dyn UserRepository>,
    pub sessions: Arc<dyn SessionRepository>,
    pub notes: Arc<dyn NoteRepository>,
    pub auth_attempts: Arc<dyn AuthAttemptRepository>,
}

impl VaultRepositories {
    /// Builds repository handles backed by an [`memory::InMemoryStore`].
    #[must_use]
    pub fn from_in_memory(store: Arc<memory::InMemoryStore>) -> Self {
        Self {
            users: Arc::clone(&store) as Arc<dyn UserRepository>,
            sessions: Arc::clone(&store) as Arc<dyn SessionRepository>,
            notes: Arc::clone(&store) as Arc<dyn NoteRepository>,
            auth_attempts: store as Arc<dyn AuthAttemptRepository>,
        }
    }

    /// Builds repository handles backed by a [`pg::PgStore`].
    #[must_use]
    pub fn from_pg(store: Arc<pg::PgStore>) -> Self {
        Self {
            users: Arc::clone(&store) as Arc<dyn UserRepository>,
            sessions: Arc::clone(&store) as Arc<dyn SessionRepository>,
            notes: Arc::clone(&store) as Arc<dyn NoteRepository>,
            auth_attempts: store as Arc<dyn AuthAttemptRepository>,
        }
    }
}
