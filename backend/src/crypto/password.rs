//! Password validation and Argon2id hashing/verification on Tokio's blocking pool.

use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
    password_hash::{SaltString, rand_core::OsRng},
};
use secrecy::{ExposeSecret, SecretString};

use crate::crypto::CryptoError;

/// Minimum password length in Unicode scalar values.
pub const MIN_PASSWORD_LEN: usize = 12;

/// Maximum password length in Unicode scalar values.
pub const MAX_PASSWORD_LEN: usize = 128;

/// Maximum password byte length to prevent multi-byte `DoS` payloads.
const MAX_PASSWORD_BYTES: usize = 512;

/// OWASP 2025 compliant Argon2id memory cost (19 MiB = 19,456 KiB).
const ARGON2_MEMORY_KIB: u32 = 19_456;

/// OWASP 2025 compliant Argon2id iteration count.
const ARGON2_TIME_COST: u32 = 2;

/// OWASP 2025 compliant Argon2id parallelism factor.
const ARGON2_PARALLELISM: u32 = 1;

/// Output hash length in bytes.
const ARGON2_OUTPUT_LEN: usize = 32;

/// Validates password length rules (12..=128 characters, <= 512 UTF-8 bytes).
pub fn validate_password(password: &str) -> Result<(), CryptoError> {
    let char_count = password.chars().count();
    if char_count < MIN_PASSWORD_LEN {
        return Err(CryptoError::PasswordTooShort {
            min: MIN_PASSWORD_LEN,
        });
    }
    if char_count > MAX_PASSWORD_LEN || password.len() > MAX_PASSWORD_BYTES {
        return Err(CryptoError::PasswordTooLong {
            max: MAX_PASSWORD_LEN,
        });
    }
    Ok(())
}

fn build_argon2() -> Result<Argon2<'static>, CryptoError> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        Some(ARGON2_OUTPUT_LEN),
    )
    .map_err(|_| CryptoError::PasswordHashingFailed)?;

    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Validates and hashes a password using Argon2id inside `tokio::task::spawn_blocking`.
pub async fn hash_password(password: SecretString) -> Result<SecretString, CryptoError> {
    validate_password(password.expose_secret())?;

    tokio::task::spawn_blocking(move || {
        let argon2 = build_argon2()?;
        let salt = SaltString::generate(&mut OsRng);
        let hash = argon2
            .hash_password(password.expose_secret().as_bytes(), &salt)
            .map_err(|_| CryptoError::PasswordHashingFailed)?;
        Ok(SecretString::from(hash.to_string()))
    })
    .await
    .map_err(|_| CryptoError::TaskJoinError)?
}

/// Verifies a plaintext password against a stored PHC Argon2id hash in constant time
/// inside `tokio::task::spawn_blocking`.
pub async fn verify_password(
    password: SecretString,
    stored_hash: SecretString,
) -> Result<bool, CryptoError> {
    if password.expose_secret().len() > MAX_PASSWORD_BYTES {
        return Ok(false);
    }

    tokio::task::spawn_blocking(move || {
        let parsed_hash = PasswordHash::new(stored_hash.expose_secret())
            .map_err(|_| CryptoError::PasswordHashInvalid)?;
        let argon2 = build_argon2()?;
        match argon2.verify_password(password.expose_secret().as_bytes(), &parsed_hash) {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(_) => Err(CryptoError::PasswordHashInvalid),
        }
    })
    .await
    .map_err(|_| CryptoError::TaskJoinError)?
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_and_long_passwords() {
        assert_eq!(
            validate_password("short12345"),
            Err(CryptoError::PasswordTooShort { min: 12 })
        );
        assert!(validate_password("ValidPass#12").is_ok());

        let exact_max = "a".repeat(128);
        assert!(validate_password(&exact_max).is_ok());

        let too_long = "a".repeat(129);
        assert_eq!(
            validate_password(&too_long),
            Err(CryptoError::PasswordTooLong { max: 128 })
        );
    }

    #[tokio::test]
    async fn hashes_and_verifies_password_roundtrip() {
        let secret = SecretString::from("StrongVaultPassword#2026");
        let hash = hash_password(secret.clone()).await.unwrap();

        assert!(hash.expose_secret().starts_with("$argon2id$v=19$"));
        assert!(verify_password(secret, hash.clone()).await.unwrap());
        assert!(
            !verify_password(SecretString::from("WrongVaultPassword#2026"), hash)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn generates_unique_salts_for_same_password() {
        let secret = SecretString::from("SamePassword#2026!");
        let h1 = hash_password(secret.clone()).await.unwrap();
        let h2 = hash_password(secret).await.unwrap();

        assert_ne!(h1.expose_secret(), h2.expose_secret());
    }

    #[tokio::test]
    async fn rejects_malformed_phc_hash() {
        let result = verify_password(
            SecretString::from("ValidPassword#2026"),
            SecretString::from("not-a-valid-phc-hash"),
        )
        .await;

        assert_eq!(result, Err(CryptoError::PasswordHashInvalid));
    }
}
