//! RFC 6238 TOTP (HMAC-SHA1, 6 digits, 30s period, ±1 window), local QR SVG,
//! and peppered recovery code generation/verification.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use qrcode::{QrCode, render::svg};
use rand::{RngCore, rngs::OsRng};
use secrecy::{ExposeSecret, SecretString};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::crypto::CryptoError;

/// TOTP issuer shown in authenticator applications.
pub const TOTP_ISSUER: &str = "SecurityVault";

/// Length of generated TOTP secret in bytes (160 bits per RFC 4226/6238).
pub const TOTP_SECRET_LEN: usize = 20;

/// TOTP time step in seconds.
pub const TOTP_PERIOD_SECS: u64 = 30;

/// Number of TOTP digits.
pub const TOTP_DIGITS: usize = 6;

/// Allowed clock skew in steps (±1 step = ±30 seconds).
pub const TOTP_WINDOW_STEPS: u64 = 1;

/// Number of single-use recovery codes issued on TOTP enrollment.
pub const RECOVERY_CODE_COUNT: usize = 8;

/// Unambiguous 32-character alphabet (no 0/O/1/I) for zero-bias sampling (`byte & 0x1F`).
const RECOVERY_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

// RFC 6238 / Google Authenticator / Authy / 2FAS interoperability mandates HMAC-SHA1.
type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;

/// TOTP enrollment bundle returned once during registration / setup.
#[derive(Clone)]
pub struct TotpEnrollment {
    /// Raw 20-byte secret (to be encrypted before persisting in database).
    pub raw_secret: Zeroizing<[u8; TOTP_SECRET_LEN]>,
    /// Base32 (RFC 4648, no padding) representation for manual entry.
    pub secret_base32: SecretString,
    /// `otpauth://totp/...` provisioning URI.
    pub otpauth_uri: SecretString,
    /// Self-contained SVG markup rendered locally (no external network requests).
    pub qr_svg: String,
}

impl fmt::Debug for TotpEnrollment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpEnrollment")
            .field("raw_secret", &"[REDACTED]")
            .field("secret_base32", &"[REDACTED]")
            .field("otpauth_uri", &"[REDACTED]")
            .field("qr_svg_len", &self.qr_svg.len())
            .finish()
    }
}

/// Generates a fresh 20-byte CSPRNG TOTP secret.
#[must_use]
pub fn generate_totp_secret() -> Zeroizing<[u8; TOTP_SECRET_LEN]> {
    let mut secret = Zeroizing::new([0u8; TOTP_SECRET_LEN]);
    OsRng.fill_bytes(&mut secret[..]);
    secret
}

/// Builds the full TOTP enrollment payload (Base32 secret, `otpauth://` URI, and local SVG QR).
pub fn build_totp_enrollment(
    email: &str,
    raw_secret: Zeroizing<[u8; TOTP_SECRET_LEN]>,
) -> Result<TotpEnrollment, CryptoError> {
    let secret_base32_plain = Zeroizing::new(BASE32_NOPAD.encode(&raw_secret[..]));
    let encoded_email: String = url::form_urlencoded::byte_serialize(email.as_bytes()).collect();
    let encoded_issuer: String =
        url::form_urlencoded::byte_serialize(TOTP_ISSUER.as_bytes()).collect();

    let otpauth_plain = Zeroizing::new(format!(
        "otpauth://totp/{encoded_issuer}:{encoded_email}?secret={}&issuer={encoded_issuer}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_PERIOD_SECS}",
        secret_base32_plain.as_str()
    ));

    let qr = QrCode::new(otpauth_plain.as_bytes()).map_err(|_| CryptoError::QrGenerationFailed)?;
    let qr_svg = qr
        .render::<svg::Color<'_>>()
        .min_dimensions(200, 200)
        .dark_color(svg::Color("#111827"))
        .light_color(svg::Color("#ffffff"))
        .build();

    Ok(TotpEnrollment {
        raw_secret,
        secret_base32: SecretString::from(secret_base32_plain.as_str()),
        otpauth_uri: SecretString::from(otpauth_plain.as_str()),
        qr_svg,
    })
}

/// Computes an RFC 4226 HOTP 6-digit code for a specific time-step `counter`.
pub fn generate_hotp_code(secret: &[u8], counter: u64) -> Result<String, CryptoError> {
    if secret.len() < 16 {
        return Err(CryptoError::TotpSecretInvalid);
    }

    let mut mac =
        HmacSha1::new_from_slice(secret).map_err(|_| CryptoError::TotpGenerationFailed)?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();

    let last_byte = digest
        .get(19)
        .copied()
        .ok_or(CryptoError::TotpGenerationFailed)?;
    let offset = usize::from(last_byte & 0x0f);

    let b0 = digest
        .get(offset)
        .copied()
        .ok_or(CryptoError::TotpGenerationFailed)?;
    let b1 = digest
        .get(offset + 1)
        .copied()
        .ok_or(CryptoError::TotpGenerationFailed)?;
    let b2 = digest
        .get(offset + 2)
        .copied()
        .ok_or(CryptoError::TotpGenerationFailed)?;
    let b3 = digest
        .get(offset + 3)
        .copied()
        .ok_or(CryptoError::TotpGenerationFailed)?;

    let binary = u32::from_be_bytes([b0 & 0x7f, b1, b2, b3]);
    let code = binary % 1_000_000;
    Ok(format!("{code:06}"))
}

/// Computes the 6-digit RFC 6238 TOTP code at a specific Unix timestamp (seconds).
pub fn generate_totp_at(secret: &[u8], unix_secs: u64) -> Result<String, CryptoError> {
    let counter = unix_secs / TOTP_PERIOD_SECS;
    generate_hotp_code(secret, counter)
}

/// Verifies a 6-digit TOTP code against `unix_secs` with ±1 time-step window in constant time.
pub fn verify_totp_at(secret: &[u8], code: &str, unix_secs: u64) -> Result<bool, CryptoError> {
    if secret.len() < 16 {
        return Err(CryptoError::TotpSecretInvalid);
    }

    let trimmed = code.trim();
    if trimmed.len() != TOTP_DIGITS || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(false);
    }

    let current_step = unix_secs / TOTP_PERIOD_SECS;
    let steps = [
        current_step.saturating_sub(TOTP_WINDOW_STEPS),
        current_step,
        current_step.saturating_add(TOTP_WINDOW_STEPS),
    ];

    let provided_bytes = trimmed.as_bytes();
    let mut matched: u8 = 0;

    for step in steps {
        let candidate = generate_hotp_code(secret, step)?;
        let eq = candidate.as_bytes().ct_eq(provided_bytes);
        matched |= eq.unwrap_u8();
    }

    Ok(matched == 1)
}

/// Verifies a 6-digit TOTP code against the current system wall-clock time (±1 window).
pub fn verify_totp_now(secret: &[u8], code: &str) -> Result<bool, CryptoError> {
    let unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CryptoError::TotpGenerationFailed)?
        .as_secs();
    verify_totp_at(secret, code, unix_secs)
}

/// Generates 8 random single-use recovery codes formatted as `XXXX-XXXX`.
#[must_use]
pub fn generate_recovery_codes() -> Vec<SecretString> {
    let mut codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
    let mut random_bytes = Zeroizing::new([0u8; 8]);

    for _ in 0..RECOVERY_CODE_COUNT {
        OsRng.fill_bytes(&mut random_bytes[..]);
        let mut formatted = Zeroizing::new(String::with_capacity(9));
        for (idx, byte) in random_bytes.iter().enumerate() {
            if idx == 4 {
                formatted.push('-');
            }
            let alphabet_idx = usize::from(byte & 0x1f);
            if let Some(&ch) = RECOVERY_ALPHABET.get(alphabet_idx) {
                formatted.push(char::from(ch));
            }
        }
        codes.push(SecretString::from(formatted.as_str()));
    }

    codes
}

/// Normalizes a recovery code by stripping spaces/hyphens and uppercasing.
/// Returns `None` if the normalized code does not have 8 ASCII alphanumeric characters.
#[must_use]
pub fn normalize_recovery_code(input: &str) -> Option<String> {
    let normalized: String = input
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();

    if normalized.len() == 8 && normalized.bytes().all(|b| b.is_ascii_alphanumeric()) {
        Some(normalized)
    } else {
        None
    }
}

/// Computes a keyed SHA-256 (HMAC-SHA256) 32-byte digest using `SECURITY_PEPPER` and domain separation.
pub fn keyed_sha256_bytes(
    pepper: &SecretString,
    domain: &str,
    value: &str,
) -> Result<[u8; 32], CryptoError> {
    let mut mac = HmacSha256::new_from_slice(pepper.expose_secret().as_bytes())
        .map_err(|_| CryptoError::TotpGenerationFailed)?;
    mac.update(domain.as_bytes());
    mac.update(b":");
    mac.update(value.as_bytes());
    let out: [u8; 32] = mac.finalize().into_bytes().into();
    Ok(out)
}

/// Computes a keyed SHA-256 (HMAC-SHA256) hex digest using `SECURITY_PEPPER` and domain separation.
pub fn keyed_sha256_hex(
    pepper: &SecretString,
    domain: &str,
    value: &str,
) -> Result<String, CryptoError> {
    let bytes = keyed_sha256_bytes(pepper, domain, value)?;
    Ok(hex::encode(bytes))
}

/// Hashes a recovery code with `SECURITY_PEPPER` into a 32-byte digest for PostgreSQL `BYTEA`.
pub fn hash_recovery_code_bytes(
    code: &str,
    pepper: &SecretString,
) -> Result<[u8; 32], CryptoError> {
    let normalized = normalize_recovery_code(code).ok_or(CryptoError::TotpGenerationFailed)?;
    keyed_sha256_bytes(pepper, "recovery-code", &normalized)
}

/// Hashes a recovery code with `SECURITY_PEPPER` (keyed SHA-256 hex) for string storage/comparison.
pub fn hash_recovery_code(code: &str, pepper: &SecretString) -> Result<String, CryptoError> {
    let bytes = hash_recovery_code_bytes(code, pepper)?;
    Ok(hex::encode(bytes))
}

/// Verifies a user-supplied recovery code against a stored 32-byte digest in constant time.
pub fn verify_recovery_code_bytes(
    input: &str,
    stored_hash: &[u8],
    pepper: &SecretString,
) -> Result<bool, CryptoError> {
    let Some(normalized) = normalize_recovery_code(input) else {
        return Ok(false);
    };
    let computed = keyed_sha256_bytes(pepper, "recovery-code", &normalized)?;
    if stored_hash.len() != computed.len() {
        return Ok(false);
    }
    Ok(bool::from(computed.ct_eq(stored_hash)))
}

/// Verifies a user-supplied recovery code against a stored hex hash in constant time.
pub fn verify_recovery_code(
    input: &str,
    stored_hash_hex: &str,
    pepper: &SecretString,
) -> Result<bool, CryptoError> {
    let Ok(stored_bytes) = hex::decode(stored_hash_hex) else {
        return Ok(false);
    };
    verify_recovery_code_bytes(input, &stored_bytes, pepper)
}

/// Computes an unkeyed SHA-256 32-byte digest (suitable for high-entropy 256-bit session/CSRF tokens).
#[must_use]
pub fn sha256_bytes(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Computes an unkeyed SHA-256 hex digest (suitable for high-entropy 256-bit session/CSRF tokens).
#[must_use]
pub fn sha256_hex(input: &[u8]) -> String {
    hex::encode(sha256_bytes(input))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn generates_enrollment_uri_and_local_qr_svg() {
        let secret = generate_totp_secret();
        let enrollment = build_totp_enrollment("alice@example.com", secret).unwrap();

        assert_eq!(enrollment.secret_base32.expose_secret().len(), 32);
        let uri = enrollment.otpauth_uri.expose_secret();
        assert!(uri.starts_with("otpauth://totp/SecurityVault:alice%40example.com?secret="));
        assert!(uri.contains("&issuer=SecurityVault&algorithm=SHA1&digits=6&period=30"));
        assert!(enrollment.qr_svg.contains("<svg"));
        assert!(enrollment.qr_svg.contains("</svg>"));

        let debug_str = format!("{enrollment:?}");
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains(enrollment.secret_base32.expose_secret()));
    }

    #[test]
    fn rfc_6238_sha1_test_vector_matches_standard() {
        // RFC 6238 Appendix B test vector for SHA-1:
        // Secret = "12345678901234567890" (ASCII, 20 bytes), T = 59s -> 8-digit 94287082 -> 6-digit 287082
        let secret = b"12345678901234567890";
        let code = generate_totp_at(secret, 59).unwrap();
        assert_eq!(code, "287082");
        assert!(verify_totp_at(secret, "287082", 59).unwrap());
    }

    #[test]
    fn verifies_current_and_adjacent_window_steps_and_rejects_invalid() {
        let secret = generate_totp_secret();
        let base_time = 1_700_000_015_u64;

        let current_code = generate_totp_at(&secret[..], base_time).unwrap();
        let prev_code = generate_totp_at(&secret[..], base_time - 30).unwrap();
        let next_code = generate_totp_at(&secret[..], base_time + 30).unwrap();
        let stale_code = generate_totp_at(&secret[..], base_time - 90).unwrap();

        assert!(verify_totp_at(&secret[..], &current_code, base_time).unwrap());
        assert!(verify_totp_at(&secret[..], &prev_code, base_time).unwrap());
        assert!(verify_totp_at(&secret[..], &next_code, base_time).unwrap());
        assert!(!verify_totp_at(&secret[..], &stale_code, base_time).unwrap());
        assert!(!verify_totp_at(&secret[..], "abcdef", base_time).unwrap());
        assert!(!verify_totp_at(&secret[..], "12345", base_time).unwrap());
    }

    #[test]
    fn generates_eight_unique_recovery_codes_and_verifies_with_pepper() {
        let pepper = SecretString::from("a-very-long-test-security-pepper-32chars");
        let other_pepper = SecretString::from("b-very-long-test-security-pepper-32chars");

        let codes = generate_recovery_codes();
        assert_eq!(codes.len(), 8);

        let mut seen = HashSet::new();
        for code in &codes {
            let plain = code.expose_secret();
            assert_eq!(plain.len(), 9);
            assert_eq!(plain.as_bytes()[4], b'-');
            assert!(seen.insert(plain.to_owned()));

            let hashed = hash_recovery_code(plain, &pepper).unwrap();
            assert_eq!(hashed.len(), 64);

            // Exact match, lowercase without hyphen, and trimmed whitespace all verify.
            assert!(verify_recovery_code(plain, &hashed, &pepper).unwrap());
            let lower_no_dash = plain.replace('-', "").to_lowercase();
            assert!(verify_recovery_code(&lower_no_dash, &hashed, &pepper).unwrap());

            // Wrong code or wrong pepper fails.
            assert!(!verify_recovery_code("ZZZZ-ZZZZ", &hashed, &pepper).unwrap());
            assert!(!verify_recovery_code(plain, &hashed, &other_pepper).unwrap());
        }
    }
}
