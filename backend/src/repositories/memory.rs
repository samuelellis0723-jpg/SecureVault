//! Thread-safe in-memory repository implementation for fast local and integration tests.

use std::collections::HashMap;

use time::OffsetDateTime;
use tokio::sync::RwLock;
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

#[derive(Default)]
struct StoreData {
    users: HashMap<Uuid, UserRecord>,
    recovery_codes: HashMap<Uuid, Vec<RecoveryCodeRecord>>,
    sessions: HashMap<Uuid, SessionRecord>,
    notes: HashMap<Uuid, EncryptedNoteRecord>,
    auth_attempts: Vec<AuthAttemptRecord>,
}

/// Concurrent in-memory storage implementing all repository traits.
#[derive(Default)]
pub struct InMemoryStore {
    inner: RwLock<StoreData>,
}

impl InMemoryStore {
    /// Creates an empty in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a cloned snapshot of a raw persisted note (for encryption/rotation assertions in tests).
    pub async fn inspect_note_raw(&self, note_id: Uuid) -> Option<EncryptedNoteRecord> {
        let guard = self.inner.read().await;
        guard.notes.get(&note_id).cloned()
    }

    /// Returns a cloned snapshot of a raw persisted user (for encryption/rotation assertions in tests).
    pub async fn inspect_user_raw(&self, user_id: Uuid) -> Option<UserRecord> {
        let guard = self.inner.read().await;
        guard.users.get(&user_id).cloned()
    }

    /// Mutates a raw stored note in place (used to simulate ciphertext tampering in integrity tests).
    pub async fn tamper_note_content_byte(&self, note_id: Uuid) -> bool {
        let mut guard = self.inner.write().await;
        if let Some(note) = guard.notes.get_mut(&note_id)
            && let Some(first) = note.content_ciphertext.first_mut()
        {
            *first ^= 0x01;
            return true;
        }
        false
    }
}

impl UserRepository for InMemoryStore {
    fn create_user(&self, user: UserRecord) -> RepoFuture<'_, UserRecord> {
        Box::pin(async move {
            let mut guard = self.inner.write().await;
            let email_lower = user.email.to_ascii_lowercase();
            let exists = guard
                .users
                .values()
                .any(|u| u.email.eq_ignore_ascii_case(&email_lower));
            if exists {
                return Err(AppError::conflict(
                    "EMAIL_ALREADY_EXISTS",
                    "Ya existe una cuenta registrada con ese correo",
                ));
            }
            guard.users.insert(user.id, user.clone());
            Ok(user)
        })
    }

    fn find_user_by_email<'a>(
        &'a self,
        email_lower: &'a str,
    ) -> RepoFuture<'a, Option<UserRecord>> {
        Box::pin(async move {
            let guard = self.inner.read().await;
            let found = guard
                .users
                .values()
                .find(|u| u.email.eq_ignore_ascii_case(email_lower))
                .cloned();
            Ok(found)
        })
    }

    fn find_user_by_id(&self, user_id: Uuid) -> RepoFuture<'_, Option<UserRecord>> {
        Box::pin(async move {
            let guard = self.inner.read().await;
            Ok(guard.users.get(&user_id).cloned())
        })
    }

    fn enable_totp_and_store_recovery_codes(
        &self,
        user_id: Uuid,
        recovery_codes: Vec<RecoveryCodeRecord>,
    ) -> RepoFuture<'_, UserRecord> {
        Box::pin(async move {
            let mut guard = self.inner.write().await;
            let now = OffsetDateTime::now_utc();
            let updated_user = {
                let user = guard
                    .users
                    .get_mut(&user_id)
                    .ok_or_else(|| AppError::Unauthorized("Usuario no encontrado".to_owned()))?;
                user.totp_enabled = true;
                user.failed_login_attempts = 0;
                user.locked_until = None;
                user.updated_at = now;
                user.clone()
            };
            guard.recovery_codes.insert(user_id, recovery_codes);
            Ok(updated_user)
        })
    }

    fn consume_recovery_code(
        &self,
        user_id: Uuid,
        code_hash: [u8; 32],
        now: OffsetDateTime,
    ) -> RepoFuture<'_, bool> {
        Box::pin(async move {
            let mut guard = self.inner.write().await;
            if let Some(codes) = guard.recovery_codes.get_mut(&user_id) {
                for code in codes {
                    if code.used_at.is_none() && code.code_hash == code_hash {
                        code.used_at = Some(now);
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        })
    }

    fn update_login_failure(
        &self,
        user_id: Uuid,
        failed_attempts: i16,
        locked_until: Option<OffsetDateTime>,
    ) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut guard = self.inner.write().await;
            if let Some(user) = guard.users.get_mut(&user_id) {
                user.failed_login_attempts = failed_attempts;
                user.locked_until = locked_until;
                user.updated_at = OffsetDateTime::now_utc();
            }
            Ok(())
        })
    }

    fn reset_login_failures(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut guard = self.inner.write().await;
            if let Some(user) = guard.users.get_mut(&user_id) {
                user.failed_login_attempts = 0;
                user.locked_until = None;
                user.updated_at = OffsetDateTime::now_utc();
            }
            Ok(())
        })
    }

    fn list_users_with_totp_version_ne(
        &self,
        active_version: i16,
        limit: i64,
    ) -> RepoFuture<'_, Vec<UserRecord>> {
        Box::pin(async move {
            let guard = self.inner.read().await;
            let max_items = usize::try_from(limit.max(0)).unwrap_or(0);
            let mut out: Vec<UserRecord> = guard
                .users
                .values()
                .filter(|u| u.totp_key_version != active_version)
                .cloned()
                .collect();
            out.sort_by_key(|u| u.id);
            out.truncate(max_items);
            Ok(out)
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
            let mut guard = self.inner.write().await;
            if let Some(user) = guard.users.get_mut(&user_id) {
                user.totp_secret_ciphertext = ciphertext;
                user.totp_secret_nonce = nonce;
                user.totp_key_version = key_version;
                user.updated_at = OffsetDateTime::now_utc();
            }
            Ok(())
        })
    }
}

impl SessionRepository for InMemoryStore {
    fn create_session(&self, session: SessionRecord) -> RepoFuture<'_, SessionRecord> {
        Box::pin(async move {
            let mut guard = self.inner.write().await;
            guard.sessions.insert(session.id, session.clone());
            Ok(session)
        })
    }

    fn find_session_by_token_hash(
        &self,
        token_hash: [u8; 32],
    ) -> RepoFuture<'_, Option<SessionRecord>> {
        Box::pin(async move {
            let guard = self.inner.read().await;
            let found = guard
                .sessions
                .values()
                .find(|s| s.token_hash == token_hash)
                .cloned();
            Ok(found)
        })
    }

    fn touch_session(&self, session_id: Uuid, last_seen_at: OffsetDateTime) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut guard = self.inner.write().await;
            if let Some(session) = guard.sessions.get_mut(&session_id) {
                session.last_seen_at = last_seen_at;
            }
            Ok(())
        })
    }

    fn revoke_session(&self, session_id: Uuid, revoked_at: OffsetDateTime) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut guard = self.inner.write().await;
            if let Some(session) = guard.sessions.get_mut(&session_id) {
                session.revoked_at = Some(revoked_at);
            }
            Ok(())
        })
    }

    fn revoke_all_user_sessions(
        &self,
        user_id: Uuid,
        revoked_at: OffsetDateTime,
    ) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut guard = self.inner.write().await;
            for session in guard.sessions.values_mut() {
                if session.user_id == user_id && session.revoked_at.is_none() {
                    session.revoked_at = Some(revoked_at);
                }
            }
            Ok(())
        })
    }
}

impl NoteRepository for InMemoryStore {
    fn create_note(&self, note: EncryptedNoteRecord) -> RepoFuture<'_, EncryptedNoteRecord> {
        Box::pin(async move {
            let mut guard = self.inner.write().await;
            guard.notes.insert(note.id, note.clone());
            Ok(note)
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
            let guard = self.inner.read().await;
            let mut filtered: Vec<EncryptedNoteRecord> = guard
                .notes
                .values()
                .filter(|n| n.user_id == user_id && category.is_none_or(|c| n.category == c))
                .cloned()
                .collect();

            filtered.sort_by(|a, b| {
                b.created_at
                    .cmp(&a.created_at)
                    .then_with(|| b.id.cmp(&a.id))
            });

            let total = u64::try_from(filtered.len()).unwrap_or(u64::MAX);
            let safe_page = usize::try_from(page.max(1)).unwrap_or(1);
            let safe_limit = usize::try_from(limit.max(1)).unwrap_or(20);
            let offset = safe_page.saturating_sub(1).saturating_mul(safe_limit);

            let items = if offset >= filtered.len() {
                Vec::new()
            } else {
                filtered.into_iter().skip(offset).take(safe_limit).collect()
            };

            Ok((items, total))
        })
    }

    fn find_note_by_id(
        &self,
        note_id: Uuid,
        user_id: Uuid,
    ) -> RepoFuture<'_, Option<EncryptedNoteRecord>> {
        Box::pin(async move {
            let guard = self.inner.read().await;
            Ok(guard
                .notes
                .get(&note_id)
                .filter(|n| n.user_id == user_id)
                .cloned())
        })
    }

    fn update_note(
        &self,
        mut note: EncryptedNoteRecord,
    ) -> RepoFuture<'_, Option<EncryptedNoteRecord>> {
        Box::pin(async move {
            let mut guard = self.inner.write().await;
            let Some(existing) = guard.notes.get(&note.id) else {
                return Ok(None);
            };
            if existing.user_id != note.user_id {
                return Ok(None);
            }
            note.created_at = existing.created_at;
            note.updated_at = OffsetDateTime::now_utc();
            guard.notes.insert(note.id, note.clone());
            Ok(Some(note))
        })
    }

    fn delete_note(&self, note_id: Uuid, user_id: Uuid) -> RepoFuture<'_, bool> {
        Box::pin(async move {
            let mut guard = self.inner.write().await;
            let owned = guard
                .notes
                .get(&note_id)
                .is_some_and(|n| n.user_id == user_id);
            if owned {
                guard.notes.remove(&note_id);
                Ok(true)
            } else {
                Ok(false)
            }
        })
    }

    fn list_notes_with_key_version_ne(
        &self,
        active_version: i16,
        limit: i64,
    ) -> RepoFuture<'_, Vec<EncryptedNoteRecord>> {
        Box::pin(async move {
            let guard = self.inner.read().await;
            let max_items = usize::try_from(limit.max(0)).unwrap_or(0);
            let mut out: Vec<EncryptedNoteRecord> = guard
                .notes
                .values()
                .filter(|n| n.key_version != active_version)
                .cloned()
                .collect();
            out.sort_by_key(|n| n.id);
            out.truncate(max_items);
            Ok(out)
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
            let mut guard = self.inner.write().await;
            if let Some(note) = guard.notes.get_mut(&note_id)
                && note.user_id == user_id
            {
                note.title_ciphertext = title_ciphertext;
                note.title_nonce = title_nonce;
                note.content_ciphertext = content_ciphertext;
                note.content_nonce = content_nonce;
                note.key_version = key_version;
                note.updated_at = OffsetDateTime::now_utc();
                return Ok(true);
            }
            Ok(false)
        })
    }
}

impl AuthAttemptRepository for InMemoryStore {
    fn record_attempt(&self, attempt: AuthAttemptRecord) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut guard = self.inner.write().await;
            guard.auth_attempts.push(attempt);
            Ok(())
        })
    }

    fn count_recent_failures(
        &self,
        identifier_hash: [u8; 32],
        since: OffsetDateTime,
    ) -> RepoFuture<'_, u64> {
        Box::pin(async move {
            let guard = self.inner.read().await;
            let count = guard
                .auth_attempts
                .iter()
                .filter(|a| {
                    a.identifier_hash == identifier_hash && !a.succeeded && a.created_at >= since
                })
                .count();
            Ok(u64::try_from(count).unwrap_or(u64::MAX))
        })
    }
}
