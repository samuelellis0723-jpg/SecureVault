//! Idempotent batch key rotation service for encrypted notes and user TOTP secrets.

use crate::crypto::cipher::{
    AAD_ENTITY_NOTE_CONTENT, AAD_ENTITY_NOTE_TITLE, AAD_ENTITY_TOTP_SECRET, KeyRing,
};
use crate::domain::error::AppError;
use crate::repositories::VaultRepositories;

/// Default number of records processed per batch during key rotation.
pub const DEFAULT_ROTATION_BATCH_SIZE: i64 = 100;

/// Summary counts produced by [`rotate_all_keys`] (contains zero sensitive material).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationReport {
    pub active_version: i16,
    pub notes_rotated: u64,
    pub users_rotated: u64,
}

/// Re-encrypts in idempotent batches all notes where `key_version != active_version`
/// and all users where `totp_key_version != active_version` using the active key in `key_ring`.
pub async fn rotate_all_keys(
    repos: &VaultRepositories,
    key_ring: &KeyRing,
    batch_size: i64,
) -> Result<RotationReport, AppError> {
    let active_version = key_ring.active_version();
    let effective_batch = batch_size.max(1);

    let mut notes_rotated: u64 = 0;
    loop {
        let batch = repos
            .notes
            .list_notes_with_key_version_ne(active_version, effective_batch)
            .await?;
        if batch.is_empty() {
            break;
        }

        for note in batch {
            let plain_title = key_ring.decrypt_parts(
                &note.title_ciphertext,
                &note.title_nonce,
                note.key_version,
                note.user_id,
                AAD_ENTITY_NOTE_TITLE,
                note.id,
            )?;
            let plain_content = key_ring.decrypt_parts(
                &note.content_ciphertext,
                &note.content_nonce,
                note.key_version,
                note.user_id,
                AAD_ENTITY_NOTE_CONTENT,
                note.id,
            )?;

            let new_title = key_ring.encrypt(
                &plain_title[..],
                note.user_id,
                AAD_ENTITY_NOTE_TITLE,
                note.id,
            )?;
            let new_content = key_ring.encrypt(
                &plain_content[..],
                note.user_id,
                AAD_ENTITY_NOTE_CONTENT,
                note.id,
            )?;

            let updated = repos
                .notes
                .update_note_encryption(
                    note.id,
                    note.user_id,
                    new_title.ciphertext,
                    new_title.nonce.to_vec(),
                    new_content.ciphertext,
                    new_content.nonce.to_vec(),
                    active_version,
                )
                .await?;
            if updated {
                notes_rotated = notes_rotated.saturating_add(1);
            }
        }
    }

    let mut users_rotated: u64 = 0;
    loop {
        let batch = repos
            .users
            .list_users_with_totp_version_ne(active_version, effective_batch)
            .await?;
        if batch.is_empty() {
            break;
        }

        for user in batch {
            let plain_totp = key_ring.decrypt_parts(
                &user.totp_secret_ciphertext,
                &user.totp_secret_nonce,
                user.totp_key_version,
                user.id,
                AAD_ENTITY_TOTP_SECRET,
                user.id,
            )?;

            let new_totp =
                key_ring.encrypt(&plain_totp[..], user.id, AAD_ENTITY_TOTP_SECRET, user.id)?;

            repos
                .users
                .update_user_totp_secret(
                    user.id,
                    new_totp.ciphertext,
                    new_totp.nonce.to_vec(),
                    active_version,
                )
                .await?;
            users_rotated = users_rotated.saturating_add(1);
        }
    }

    Ok(RotationReport {
        active_version,
        notes_rotated,
        users_rotated,
    })
}
