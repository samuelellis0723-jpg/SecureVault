//! Domain entities, value objects, and API response envelopes aligned with
//! `esquema-bd.md` and `contrato-api.md`.

use std::fmt;
use std::str::FromStr;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Closed enumeration of note categories supported by `SecurityVault`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NoteCategory {
    General,
    Personal,
    Finanzas,
    Credenciales,
    Documentos,
}

impl NoteCategory {
    /// Returns the canonical lowercase string stored in PostgreSQL and exposed in JSON.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::General => "general",
            Self::Personal => "personal",
            Self::Finanzas => "finanzas",
            Self::Credenciales => "credenciales",
            Self::Documentos => "documentos",
        }
    }
}

impl fmt::Display for NoteCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for NoteCategory {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "general" => Ok(Self::General),
            "personal" => Ok(Self::Personal),
            "finanzas" => Ok(Self::Finanzas),
            "credenciales" => Ok(Self::Credenciales),
            "documentos" => Ok(Self::Documentos),
            _ => Err("invalid note category"),
        }
    }
}

/// Kind of authentication challenge recorded in `auth_attempts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthAttemptType {
    Login,
    Totp,
    Recovery,
}

impl AuthAttemptType {
    /// Returns the canonical database string for `auth_attempts.attempt_type`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Totp => "totp",
            Self::Recovery => "recovery",
        }
    }
}

impl fmt::Display for AuthAttemptType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AuthAttemptType {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "login" => Ok(Self::Login),
            "totp" => Ok(Self::Totp),
            "recovery" => Ok(Self::Recovery),
            _ => Err("invalid auth attempt type"),
        }
    }
}

/// Persisted user entity aligned with table `users`.
#[derive(Clone)]
pub struct UserRecord {
    pub id: Uuid,
    pub email: String,
    pub password_hash: SecretString,
    pub totp_secret_ciphertext: Vec<u8>,
    pub totp_secret_nonce: Vec<u8>,
    pub totp_key_version: i16,
    pub totp_enabled: bool,
    pub failed_login_attempts: i16,
    pub locked_until: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl fmt::Debug for UserRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserRecord")
            .field("id", &self.id)
            .field("password_hash", &"[REDACTED]")
            .field("totp_secret_ciphertext", &"[REDACTED]")
            .field("totp_key_version", &self.totp_key_version)
            .field("totp_enabled", &self.totp_enabled)
            .field("failed_login_attempts", &self.failed_login_attempts)
            .field("locked_until", &self.locked_until)
            .finish_non_exhaustive()
    }
}

/// Safe public projection of a user returned in API responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserPublic {
    pub id: Uuid,
    pub email: String,
}

impl From<&UserRecord> for UserPublic {
    fn from(user: &UserRecord) -> Self {
        Self {
            id: user.id,
            email: user.email.clone(),
        }
    }
}

/// Persisted single-use TOTP recovery code hash aligned with table `totp_recovery_codes`.
#[derive(Clone)]
pub struct RecoveryCodeRecord {
    pub id: Uuid,
    pub user_id: Uuid,
    pub code_hash: [u8; 32],
    pub used_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

impl fmt::Debug for RecoveryCodeRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryCodeRecord")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("code_hash", &"[REDACTED]")
            .field("used_at", &self.used_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Persisted server-side session aligned with table `sessions`.
#[derive(Clone)]
pub struct SessionRecord {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: [u8; 32],
    pub csrf_token_hash: [u8; 32],
    pub mfa_verified: bool,
    pub last_seen_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

impl fmt::Debug for SessionRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRecord")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("token_hash", &"[REDACTED]")
            .field("csrf_token_hash", &"[REDACTED]")
            .field("mfa_verified", &self.mfa_verified)
            .field("last_seen_at", &self.last_seen_at)
            .field("expires_at", &self.expires_at)
            .field("revoked_at", &self.revoked_at)
            .finish_non_exhaustive()
    }
}

/// Persisted encrypted note entity aligned with table `notes` (zero plaintext).
#[derive(Clone)]
pub struct EncryptedNoteRecord {
    pub id: Uuid,
    pub user_id: Uuid,
    pub category: NoteCategory,
    pub title_ciphertext: Vec<u8>,
    pub title_nonce: Vec<u8>,
    pub content_ciphertext: Vec<u8>,
    pub content_nonce: Vec<u8>,
    pub key_version: i16,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl fmt::Debug for EncryptedNoteRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedNoteRecord")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("category", &self.category)
            .field("key_version", &self.key_version)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish_non_exhaustive()
    }
}

/// Summary view of a decrypted note returned in `GET /api/v1/notes`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteSummary {
    pub id: Uuid,
    pub title: String,
    pub category: NoteCategory,
    pub key_version: i16,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// Full decrypted note returned in `POST /api/v1/notes`, `GET /api/v1/notes/:id`,
/// and `PATCH /api/v1/notes/:id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteDetail {
    pub id: Uuid,
    pub title: String,
    pub content: String,
    pub category: NoteCategory,
    pub key_version: i16,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// Authentication attempt record aligned with table `auth_attempts`.
#[derive(Clone)]
pub struct AuthAttemptRecord {
    pub id: Uuid,
    pub identifier_hash: [u8; 32],
    pub ip_hash: [u8; 32],
    pub attempt_type: AuthAttemptType,
    pub succeeded: bool,
    pub created_at: OffsetDateTime,
}

impl fmt::Debug for AuthAttemptRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthAttemptRecord")
            .field("id", &self.id)
            .field("attempt_type", &self.attempt_type)
            .field("succeeded", &self.succeeded)
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

/// Standard pagination metadata matching `contrato-api.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaginationMeta {
    pub total: u64,
    pub page: u32,
    pub limit: u32,
    #[serde(rename = "totalPages")]
    pub total_pages: u32,
}

impl PaginationMeta {
    /// Computes pagination metadata safely without overflow or division by zero.
    #[must_use]
    pub fn new(total: u64, page: u32, limit: u32) -> Self {
        let safe_limit = limit.max(1);
        let total_pages = if total == 0 {
            0
        } else {
            let pages = total.div_ceil(u64::from(safe_limit));
            u32::try_from(pages).unwrap_or(u32::MAX)
        };
        Self {
            total,
            page: page.max(1),
            limit: safe_limit,
            total_pages,
        }
    }
}

/// Standard JSON success response envelope without pagination metadata.
#[derive(Debug, Serialize)]
pub struct ApiSuccess<T: Serialize> {
    pub success: bool,
    pub data: T,
}

impl<T: Serialize> ApiSuccess<T> {
    /// Wraps `data` in `{ "success": true, "data": ... }`.
    #[must_use]
    pub const fn new(data: T) -> Self {
        Self {
            success: true,
            data,
        }
    }
}

/// Standard JSON success response envelope with pagination metadata.
#[derive(Debug, Serialize)]
pub struct ApiSuccessWithMeta<T: Serialize, M: Serialize> {
    pub success: bool,
    pub data: T,
    pub meta: M,
}

impl<T: Serialize, M: Serialize> ApiSuccessWithMeta<T, M> {
    /// Wraps `data` and `meta` in `{ "success": true, "data": ..., "meta": ... }`.
    #[must_use]
    pub const fn new(data: T, meta: M) -> Self {
        Self {
            success: true,
            data,
            meta,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn note_category_roundtrip_serde_and_from_str() {
        let categories = [
            (NoteCategory::General, "general"),
            (NoteCategory::Personal, "personal"),
            (NoteCategory::Finanzas, "finanzas"),
            (NoteCategory::Credenciales, "credenciales"),
            (NoteCategory::Documentos, "documentos"),
        ];

        for (cat, expected) in categories {
            assert_eq!(cat.as_str(), expected);
            assert_eq!(NoteCategory::from_str(expected).unwrap(), cat);
            let json = serde_json::to_string(&cat).unwrap();
            assert_eq!(json, format!("\"{expected}\""));
            let parsed: NoteCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, cat);
        }

        assert!(NoteCategory::from_str("secreto").is_err());
        assert!(serde_json::from_str::<NoteCategory>("\"secreto\"").is_err());
    }

    #[test]
    fn pagination_meta_computes_zero_and_non_zero_pages() {
        let empty = PaginationMeta::new(0, 1, 20);
        assert_eq!(empty.total_pages, 0);
        assert_eq!(empty.page, 1);

        let exact = PaginationMeta::new(40, 2, 20);
        assert_eq!(exact.total_pages, 2);

        let partial = PaginationMeta::new(41, 1, 20);
        assert_eq!(partial.total_pages, 3);
    }

    #[test]
    fn note_detail_serializes_timestamps_as_rfc3339() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let note = NoteDetail {
            id: Uuid::nil(),
            title: "Test".to_owned(),
            content: "Secret".to_owned(),
            category: NoteCategory::General,
            key_version: 1,
            created_at: now,
            updated_at: now,
        };
        let json = serde_json::to_value(&note).unwrap();
        assert_eq!(json["created_at"], "1970-01-01T00:00:00Z");
        assert_eq!(json["category"], "general");
    }
}
