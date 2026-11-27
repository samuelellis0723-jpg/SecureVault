//! Encrypted private notes CRUD service with AES-256-GCM + AAD and strict BOLA isolation.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::crypto::{
    CryptoError,
    cipher::{AAD_ENTITY_NOTE_CONTENT, AAD_ENTITY_NOTE_TITLE, KeyRing},
};
use crate::domain::{
    error::AppError,
    models::{EncryptedNoteRecord, NoteCategory, NoteDetail, NoteSummary, PaginationMeta},
};
use crate::repositories::VaultRepositories;
use crate::services::alerts::{AlertEventKind, AlertService};

/// Maximum title length in Unicode scalar values (`contrato-api.md`).
pub const MAX_NOTE_TITLE_CHARS: usize = 200;

/// Maximum content length in Unicode scalar values (`contrato-api.md`).
pub const MAX_NOTE_CONTENT_CHARS: usize = 50_000;

/// Default pagination page number.
pub const DEFAULT_PAGE: u32 = 1;

/// Default page size for `GET /api/v1/notes`.
pub const DEFAULT_LIMIT: u32 = 20;

/// Maximum allowed page size for `GET /api/v1/notes` (`contrato-api.md`).
pub const MAX_LIMIT: u32 = 100;

/// Service managing encrypted user notes.
#[derive(Clone)]
pub struct NotesService {
    repos: VaultRepositories,
    key_ring: KeyRing,
    alerts: AlertService,
}

impl NotesService {
    /// Creates a new [`NotesService`].
    #[must_use]
    pub const fn new(repos: VaultRepositories, key_ring: KeyRing, alerts: AlertService) -> Self {
        Self {
            repos,
            key_ring,
            alerts,
        }
    }

    /// Creates and encrypts a new note belonging to `user_id`.
    pub async fn create_note(
        &self,
        user_id: Uuid,
        title: &str,
        content: &str,
        category: NoteCategory,
    ) -> Result<NoteDetail, AppError> {
        let clean_title = validate_title(title)?;
        let clean_content = validate_content(content)?;

        let note_id = Uuid::new_v4();
        let title_blob = self.key_ring.encrypt(
            clean_title.as_bytes(),
            user_id,
            AAD_ENTITY_NOTE_TITLE,
            note_id,
        )?;
        let content_blob = self.key_ring.encrypt(
            clean_content.as_bytes(),
            user_id,
            AAD_ENTITY_NOTE_CONTENT,
            note_id,
        )?;

        let now = OffsetDateTime::now_utc();
        let record = EncryptedNoteRecord {
            id: note_id,
            user_id,
            category,
            title_ciphertext: title_blob.ciphertext,
            title_nonce: title_blob.nonce.to_vec(),
            content_ciphertext: content_blob.ciphertext,
            content_nonce: content_blob.nonce.to_vec(),
            key_version: title_blob.key_version,
            created_at: now,
            updated_at: now,
        };

        let stored = self.repos.notes.create_note(record).await?;

        Ok(NoteDetail {
            id: stored.id,
            title: clean_title.to_owned(),
            content: clean_content.to_owned(),
            category: stored.category,
            key_version: stored.key_version,
            created_at: stored.created_at,
            updated_at: stored.updated_at,
        })
    }

    /// Lists paginated note summaries for `user_id` (ordered by `created_at DESC`).
    pub async fn list_notes(
        &self,
        user_id: Uuid,
        category: Option<NoteCategory>,
        page: u32,
        limit: u32,
        client_ip: &str,
        request_id: &str,
    ) -> Result<(Vec<NoteSummary>, PaginationMeta), AppError> {
        if page < 1 {
            return Err(AppError::validation(
                "El parámetro 'page' debe ser un entero mayor o igual a 1",
            ));
        }
        if !(1..=MAX_LIMIT).contains(&limit) {
            return Err(AppError::validation(format!(
                "El parámetro 'limit' debe estar entre 1 y {MAX_LIMIT}"
            )));
        }

        let (records, total) = self
            .repos
            .notes
            .list_notes(user_id, category, page, limit)
            .await?;

        let mut summaries = Vec::with_capacity(records.len());
        for record in records {
            let title = self.decrypt_field(
                &record.title_ciphertext,
                &record.title_nonce,
                record.key_version,
                record.user_id,
                AAD_ENTITY_NOTE_TITLE,
                record.id,
                client_ip,
                request_id,
            )?;

            summaries.push(NoteSummary {
                id: record.id,
                title,
                category: record.category,
                key_version: record.key_version,
                created_at: record.created_at,
                updated_at: record.updated_at,
            });
        }

        let meta = PaginationMeta::new(total, page, limit);
        Ok((summaries, meta))
    }

    /// Fetches and decrypts a single note strictly owned by `user_id`.
    pub async fn get_note(
        &self,
        user_id: Uuid,
        note_id: Uuid,
        client_ip: &str,
        request_id: &str,
    ) -> Result<NoteDetail, AppError> {
        let record = self
            .repos
            .notes
            .find_note_by_id(note_id, user_id)
            .await?
            .ok_or(AppError::NotFound)?;

        let title = self.decrypt_field(
            &record.title_ciphertext,
            &record.title_nonce,
            record.key_version,
            record.user_id,
            AAD_ENTITY_NOTE_TITLE,
            record.id,
            client_ip,
            request_id,
        )?;
        let content = self.decrypt_field(
            &record.content_ciphertext,
            &record.content_nonce,
            record.key_version,
            record.user_id,
            AAD_ENTITY_NOTE_CONTENT,
            record.id,
            client_ip,
            request_id,
        )?;

        Ok(NoteDetail {
            id: record.id,
            title,
            content,
            category: record.category,
            key_version: record.key_version,
            created_at: record.created_at,
            updated_at: record.updated_at,
        })
    }

    /// Partially updates a note owned by `user_id`, re-encrypting both `title` and `content`
    /// with the active key version and fresh 96-bit nonces.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_note(
        &self,
        user_id: Uuid,
        note_id: Uuid,
        title: Option<&str>,
        content: Option<&str>,
        category: Option<NoteCategory>,
        client_ip: &str,
        request_id: &str,
    ) -> Result<NoteDetail, AppError> {
        if title.is_none() && content.is_none() && category.is_none() {
            return Err(AppError::validation(
                "Debes proporcionar al menos un campo para actualizar (title, content o category)",
            ));
        }

        let validated_title = title.map(validate_title).transpose()?;
        let validated_content = content.map(validate_content).transpose()?;

        let existing = self
            .repos
            .notes
            .find_note_by_id(note_id, user_id)
            .await?
            .ok_or(AppError::NotFound)?;

        // Always decrypt existing values to verify AEAD integrity and re-encrypt both
        // fields consistently under the active key version with fresh nonces.
        let existing_title = self.decrypt_field(
            &existing.title_ciphertext,
            &existing.title_nonce,
            existing.key_version,
            existing.user_id,
            AAD_ENTITY_NOTE_TITLE,
            existing.id,
            client_ip,
            request_id,
        )?;
        let existing_content = self.decrypt_field(
            &existing.content_ciphertext,
            &existing.content_nonce,
            existing.key_version,
            existing.user_id,
            AAD_ENTITY_NOTE_CONTENT,
            existing.id,
            client_ip,
            request_id,
        )?;

        let final_title = validated_title.map_or(existing_title, str::to_owned);
        let final_content = validated_content.map_or(existing_content, str::to_owned);
        let final_category = category.unwrap_or(existing.category);

        let title_blob = self.key_ring.encrypt(
            final_title.as_bytes(),
            user_id,
            AAD_ENTITY_NOTE_TITLE,
            note_id,
        )?;
        let content_blob = self.key_ring.encrypt(
            final_content.as_bytes(),
            user_id,
            AAD_ENTITY_NOTE_CONTENT,
            note_id,
        )?;

        let updated_record = EncryptedNoteRecord {
            id: existing.id,
            user_id: existing.user_id,
            category: final_category,
            title_ciphertext: title_blob.ciphertext,
            title_nonce: title_blob.nonce.to_vec(),
            content_ciphertext: content_blob.ciphertext,
            content_nonce: content_blob.nonce.to_vec(),
            key_version: title_blob.key_version,
            created_at: existing.created_at,
            updated_at: OffsetDateTime::now_utc(),
        };

        let persisted = self
            .repos
            .notes
            .update_note(updated_record)
            .await?
            .ok_or(AppError::NotFound)?;

        Ok(NoteDetail {
            id: persisted.id,
            title: final_title,
            content: final_content,
            category: persisted.category,
            key_version: persisted.key_version,
            created_at: persisted.created_at,
            updated_at: persisted.updated_at,
        })
    }

    /// Deletes a note owned by `user_id`, returning `404 NOT_FOUND` if missing or owned by another user.
    pub async fn delete_note(&self, user_id: Uuid, note_id: Uuid) -> Result<(), AppError> {
        let deleted = self.repos.notes.delete_note(note_id, user_id).await?;
        if deleted {
            Ok(())
        } else {
            Err(AppError::NotFound)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn decrypt_field(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        key_version: i16,
        user_id: Uuid,
        entity: &str,
        note_id: Uuid,
        client_ip: &str,
        request_id: &str,
    ) -> Result<String, AppError> {
        let plain_bytes = self
            .key_ring
            .decrypt_parts(ciphertext, nonce, key_version, user_id, entity, note_id)
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
            })?;

        String::from_utf8(plain_bytes.to_vec()).map_err(|_| {
            self.alerts.notify(
                AlertEventKind::CryptoIntegrityFailure,
                request_id,
                client_ip,
                "INTERNAL_ERROR",
            );
            AppError::CryptoIntegrity("decrypted note field is not valid UTF-8".to_owned())
        })
    }
}

fn validate_title(raw: &str) -> Result<&str, AppError> {
    let trimmed = raw.trim();
    let count = trimmed.chars().count();
    if count == 0 {
        return Err(AppError::validation("El título de la nota es obligatorio"));
    }
    if count > MAX_NOTE_TITLE_CHARS {
        return Err(AppError::validation(format!(
            "El título no puede superar los {MAX_NOTE_TITLE_CHARS} caracteres"
        )));
    }
    Ok(trimmed)
}

fn validate_content(raw: &str) -> Result<&str, AppError> {
    let trimmed = raw.trim();
    let count = trimmed.chars().count();
    if count == 0 {
        return Err(AppError::validation(
            "El contenido de la nota es obligatorio",
        ));
    }
    if count > MAX_NOTE_CONTENT_CHARS {
        return Err(AppError::validation(format!(
            "El contenido no puede superar los {MAX_NOTE_CONTENT_CHARS} caracteres"
        )));
    }
    Ok(trimmed)
}
