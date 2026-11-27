//! Cryptographic primitives for `SecurityVault`.

pub mod cipher;
pub mod password;
pub mod totp;

use thiserror::Error;

/// Unified error type for cryptographic operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    /// Key material is not valid hexadecimal.
    #[error("encryption key is not valid hexadecimal")]
    InvalidKeyHex,

    /// Key material does not have the required 32-byte length.
    #[error("encryption key must be exactly 32 bytes (64 hex characters)")]
    InvalidKeyLength,

    /// Requested key version is not present in the key ring.
    #[error("key version {0} not found in key ring")]
    KeyVersionNotFound(i16),

    /// Key version must be >= 1.
    #[error("invalid key version {0}: must be >= 1")]
    InvalidKeyVersion(i16),

    /// Key ring must contain at least one key.
    #[error("key ring cannot be empty")]
    EmptyKeyRing,

    /// AES-256-GCM encryption failed.
    #[error("encryption failed")]
    EncryptionFailed,

    /// AEAD authentication tag verification failed (tampering or AAD mismatch).
    #[error("ciphertext integrity check failed")]
    IntegrityFailure,

    /// Nonce length does not match AES-256-GCM 96-bit requirement.
    #[error("nonce must be exactly 12 bytes")]
    InvalidNonceLength,

    /// Password does not satisfy minimum length requirement.
    #[error("password must be at least {min} characters long")]
    PasswordTooShort {
        /// Minimum allowed character count.
        min: usize,
    },

    /// Password exceeds maximum length requirement.
    #[error("password must be at most {max} characters long")]
    PasswordTooLong {
        /// Maximum allowed character count.
        max: usize,
    },

    /// Argon2id hashing failed.
    #[error("password hashing failed")]
    PasswordHashingFailed,

    /// Stored PHC password hash is malformed.
    #[error("stored password hash is invalid")]
    PasswordHashInvalid,

    /// TOTP secret length or encoding is invalid.
    #[error("totp secret is invalid")]
    TotpSecretInvalid,

    /// TOTP computation failed.
    #[error("totp computation failed")]
    TotpGenerationFailed,

    /// Local QR SVG rendering failed.
    #[error("qr svg rendering failed")]
    QrGenerationFailed,

    /// Blocking worker task failed to join.
    #[error("cryptographic worker task failed")]
    TaskJoinError,
}
