//! Authenticated encryption (AES-256-GCM) with structured AAD and versioned `KeyRing`.

use std::collections::HashMap;
use std::fmt;

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use rand::{RngCore, rngs::OsRng};
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::CryptoError;

/// AES-256 key length in bytes (256 bits).
pub const KEY_LEN: usize = 32;

/// AES-GCM standard nonce length in bytes (96 bits).
pub const NONCE_LEN: usize = 12;

/// Canonical AAD entity identifier for encrypted user TOTP secrets.
pub const AAD_ENTITY_TOTP_SECRET: &str = "totp_secret";

/// Canonical AAD entity identifier for encrypted note titles.
pub const AAD_ENTITY_NOTE_TITLE: &str = "note_title";

/// Canonical AAD entity identifier for encrypted note contents.
pub const AAD_ENTITY_NOTE_CONTENT: &str = "note_content";

/// Structured Additional Authenticated Data (AAD) context bound to every ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AadContext<'a> {
    /// Encryption key version used for this record.
    pub key_version: i16,
    /// Owner user identifier.
    pub user_id: Uuid,
    /// Entity kind (for example `"note_title"`, `"note_content"`, `"totp_secret"`).
    pub entity: &'a str,
    /// Specific record identifier.
    pub record_id: Uuid,
}

impl AadContext<'_> {
    /// Builds canonical AAD string: `v{key_version}|user:{user_id}|entity:{entity}|id:{record_id}`.
    #[must_use]
    pub fn build(&self) -> String {
        format!(
            "v{}|user:{}|entity:{}|id:{}",
            self.key_version, self.user_id, self.entity, self.record_id
        )
    }
}

/// Encrypted payload produced by [`KeyRing::encrypt`].
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedBlob {
    /// Ciphertext including the 128-bit GCM authentication tag.
    pub ciphertext: Vec<u8>,
    /// Random 96-bit nonce unique per encryption call.
    pub nonce: [u8; NONCE_LEN],
    /// Version of the key used to encrypt this blob.
    pub key_version: i16,
}

impl fmt::Debug for EncryptedBlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedBlob")
            .field("key_version", &self.key_version)
            .field("nonce_len", &self.nonce.len())
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

/// Versioned AES-256-GCM key ring supporting zero-downtime key rotation.
#[derive(Clone)]
pub struct KeyRing {
    active_version: i16,
    keys: HashMap<i16, Zeroizing<[u8; KEY_LEN]>>,
}

impl fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut versions: Vec<i16> = self.keys.keys().copied().collect();
        versions.sort_unstable();
        f.debug_struct("KeyRing")
            .field("active_version", &self.active_version)
            .field("loaded_versions", &versions)
            .finish()
    }
}

impl KeyRing {
    /// Creates a validated `KeyRing` from raw 32-byte zeroizing keys.
    pub fn new(
        active_version: i16,
        keys: HashMap<i16, Zeroizing<[u8; KEY_LEN]>>,
    ) -> Result<Self, CryptoError> {
        if active_version < 1 {
            return Err(CryptoError::InvalidKeyVersion(active_version));
        }
        if keys.is_empty() {
            return Err(CryptoError::EmptyKeyRing);
        }
        for &version in keys.keys() {
            if version < 1 {
                return Err(CryptoError::InvalidKeyVersion(version));
            }
        }
        if !keys.contains_key(&active_version) {
            return Err(CryptoError::KeyVersionNotFound(active_version));
        }

        Ok(Self {
            active_version,
            keys,
        })
    }

    /// Parses a 64-character hex string into a zeroizing 32-byte AES-256 key.
    pub fn decode_hex_key(raw: &SecretString) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
        let trimmed = raw.expose_secret().trim();
        if trimmed.len() != KEY_LEN * 2 {
            return Err(CryptoError::InvalidKeyLength);
        }
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        hex::decode_to_slice(trimmed, &mut key[..]).map_err(|_| CryptoError::InvalidKeyHex)?;
        Ok(key)
    }

    /// Returns the currently active key version used for new encryptions.
    #[must_use]
    pub const fn active_version(&self) -> i16 {
        self.active_version
    }

    /// Returns true if the given key version is loaded in this ring.
    #[must_use]
    pub fn has_version(&self, version: i16) -> bool {
        self.keys.contains_key(&version)
    }

    /// Returns the sorted list of loaded key versions.
    #[must_use]
    pub fn versions(&self) -> Vec<i16> {
        let mut versions: Vec<i16> = self.keys.keys().copied().collect();
        versions.sort_unstable();
        versions
    }

    /// Encrypts `plaintext` with the active key version, a fresh CSPRNG 12-byte nonce,
    /// and canonical AAD bound to `key_version`, `user_id`, `entity`, and `record_id`.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        user_id: Uuid,
        entity: &str,
        record_id: Uuid,
    ) -> Result<EncryptedBlob, CryptoError> {
        let key = self
            .keys
            .get(&self.active_version)
            .ok_or(CryptoError::KeyVersionNotFound(self.active_version))?;

        let cipher =
            Aes256Gcm::new_from_slice(&key[..]).map_err(|_| CryptoError::InvalidKeyLength)?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let aad = AadContext {
            key_version: self.active_version,
            user_id,
            entity,
            record_id,
        }
        .build();

        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed)?;

        Ok(EncryptedBlob {
            ciphertext,
            nonce: nonce_bytes,
            key_version: self.active_version,
        })
    }

    /// Decrypts an [`EncryptedBlob`] verifying its GCM tag and canonical AAD.
    ///
    /// Returns [`CryptoError::IntegrityFailure`] if ciphertext, nonce, or AAD do not match.
    pub fn decrypt(
        &self,
        blob: &EncryptedBlob,
        user_id: Uuid,
        entity: &str,
        record_id: Uuid,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let key = self
            .keys
            .get(&blob.key_version)
            .ok_or(CryptoError::KeyVersionNotFound(blob.key_version))?;

        let cipher =
            Aes256Gcm::new_from_slice(&key[..]).map_err(|_| CryptoError::InvalidKeyLength)?;

        let nonce = Nonce::from_slice(&blob.nonce);
        let aad = AadContext {
            key_version: blob.key_version,
            user_id,
            entity,
            record_id,
        }
        .build();

        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &blob.ciphertext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| CryptoError::IntegrityFailure)?;

        Ok(Zeroizing::new(plaintext))
    }

    /// Convenience helper to decrypt raw database columns (`ciphertext`, `nonce`, `key_version`).
    pub fn decrypt_parts(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        key_version: i16,
        user_id: Uuid,
        entity: &str,
        record_id: Uuid,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let nonce_arr: [u8; NONCE_LEN] = nonce
            .try_into()
            .map_err(|_| CryptoError::InvalidNonceLength)?;

        let blob = EncryptedBlob {
            ciphertext: ciphertext.to_vec(),
            nonce: nonce_arr,
            key_version,
        };

        self.decrypt(&blob, user_id, entity, record_id)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn test_key(byte: u8) -> Zeroizing<[u8; KEY_LEN]> {
        Zeroizing::new([byte; KEY_LEN])
    }

    fn single_key_ring() -> KeyRing {
        let mut keys = HashMap::new();
        keys.insert(1, test_key(0x11));
        KeyRing::new(1, keys).unwrap()
    }

    #[test]
    fn encrypt_decrypt_roundtrip_and_unique_nonces() {
        let ring = single_key_ring();
        let user_id = Uuid::new_v4();
        let note_id = Uuid::new_v4();
        let secret_text = b"Sensitive vault note payload";

        let blob1 = ring
            .encrypt(secret_text, user_id, "note:content", note_id)
            .unwrap();
        let blob2 = ring
            .encrypt(secret_text, user_id, "note:content", note_id)
            .unwrap();

        assert_eq!(blob1.key_version, 1);
        assert_ne!(blob1.nonce, blob2.nonce);
        assert_ne!(blob1.ciphertext, blob2.ciphertext);
        assert_ne!(blob1.ciphertext, secret_text);

        let decrypted1 = ring
            .decrypt(&blob1, user_id, "note:content", note_id)
            .unwrap();
        let decrypted2 = ring
            .decrypt_parts(
                &blob2.ciphertext,
                &blob2.nonce,
                blob2.key_version,
                user_id,
                "note:content",
                note_id,
            )
            .unwrap();

        assert_eq!(&decrypted1[..], secret_text);
        assert_eq!(&decrypted2[..], secret_text);
    }

    #[test]
    fn detects_single_bit_tampering() {
        let ring = single_key_ring();
        let user_id = Uuid::new_v4();
        let note_id = Uuid::new_v4();

        let mut blob = ring
            .encrypt(b"Top secret", user_id, "note:content", note_id)
            .unwrap();
        // Flip 1 bit in the first byte of ciphertext.
        blob.ciphertext[0] ^= 0x01;

        let err = ring
            .decrypt(&blob, user_id, "note:content", note_id)
            .unwrap_err();
        assert_eq!(err, CryptoError::IntegrityFailure);
    }

    #[test]
    fn rejects_mismatched_aad_user_entity_or_record() {
        let ring = single_key_ring();
        let user_a = Uuid::new_v4();
        let user_b = Uuid::new_v4();
        let note_1 = Uuid::new_v4();
        let note_2 = Uuid::new_v4();

        let blob = ring
            .encrypt(b"Private data", user_a, "note:content", note_1)
            .unwrap();

        assert_eq!(
            ring.decrypt(&blob, user_b, "note:content", note_1)
                .unwrap_err(),
            CryptoError::IntegrityFailure
        );
        assert_eq!(
            ring.decrypt(&blob, user_a, "note:title", note_1)
                .unwrap_err(),
            CryptoError::IntegrityFailure
        );
        assert_eq!(
            ring.decrypt(&blob, user_a, "note:content", note_2)
                .unwrap_err(),
            CryptoError::IntegrityFailure
        );
    }

    #[test]
    fn supports_key_rotation_v1_to_v2() {
        let user_id = Uuid::new_v4();
        let note_id = Uuid::new_v4();
        let plaintext = b"Rotate me safely";

        // Encrypt with v1 active.
        let ring_v1 = single_key_ring();
        let blob_v1 = ring_v1
            .encrypt(plaintext, user_id, "note:content", note_id)
            .unwrap();
        assert_eq!(blob_v1.key_version, 1);

        // Rotate to v2 active while retaining v1 for decryption.
        let mut keys_v2 = HashMap::new();
        keys_v2.insert(1, test_key(0x11));
        keys_v2.insert(2, test_key(0x22));
        let ring_v2 = KeyRing::new(2, keys_v2).unwrap();

        // v1 blob still decrypts cleanly.
        let decrypted_v1 = ring_v2
            .decrypt(&blob_v1, user_id, "note:content", note_id)
            .unwrap();
        assert_eq!(&decrypted_v1[..], plaintext);

        // Re-encrypt produces v2 blob.
        let blob_v2 = ring_v2
            .encrypt(&decrypted_v1, user_id, "note:content", note_id)
            .unwrap();
        assert_eq!(blob_v2.key_version, 2);

        // Decryption works even after v1 is retired.
        let mut only_v2 = HashMap::new();
        only_v2.insert(2, test_key(0x22));
        let ring_only_v2 = KeyRing::new(2, only_v2).unwrap();
        let decrypted_v2 = ring_only_v2
            .decrypt(&blob_v2, user_id, "note:content", note_id)
            .unwrap();
        assert_eq!(&decrypted_v2[..], plaintext);

        // Old v1 blob fails with KeyVersionNotFound once v1 is removed.
        assert_eq!(
            ring_only_v2
                .decrypt(&blob_v1, user_id, "note:content", note_id)
                .unwrap_err(),
            CryptoError::KeyVersionNotFound(1)
        );
    }

    #[test]
    fn debug_redacts_key_material() {
        let ring = single_key_ring();
        let debug_str = format!("{ring:?}");
        assert!(debug_str.contains("active_version: 1"));
        assert!(debug_str.contains("loaded_versions: [1]"));
        assert!(!debug_str.contains("17, 17"));
    }

    #[test]
    fn aad_format_matches_specification() {
        let user_id = Uuid::nil();
        let record_id = Uuid::nil();
        let aad = AadContext {
            key_version: 2,
            user_id,
            entity: "note:content",
            record_id,
        }
        .build();
        assert_eq!(
            aad,
            "v2|user:00000000-0000-0000-0000-000000000000|entity:note:content|id:00000000-0000-0000-0000-000000000000"
        );
    }
}
