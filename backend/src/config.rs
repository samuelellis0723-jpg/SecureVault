//! Fail-fast application configuration loader with secret redaction.

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

use crate::crypto::{
    CryptoError,
    cipher::{KEY_LEN, KeyRing},
};

/// Minimum length required for `SECURITY_PEPPER`.
pub const MIN_SECURITY_PEPPER_LEN: usize = 32;

/// Prefix for versioned AES-256-GCM encryption keys (`VAULT_KEY_V1`, `VAULT_KEY_V2`, ...).
const VAULT_KEY_PREFIX: &str = "VAULT_KEY_V";

/// Runtime environment mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppEnv {
    Development,
    Production,
    Test,
}

impl AppEnv {
    /// Returns `true` when running in production mode.
    #[must_use]
    pub const fn is_production(self) -> bool {
        matches!(self, Self::Production)
    }

    fn parse(raw: &str) -> Result<Self, ConfigError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "development" | "dev" => Ok(Self::Development),
            "production" | "prod" => Ok(Self::Production),
            "test" => Ok(Self::Test),
            other => Err(ConfigError::InvalidValue {
                var: "APP_ENV".to_owned(),
                reason: format!(
                    "unsupported value '{other}' (expected development|production|test)"
                ),
            }),
        }
    }
}

/// Supported external alert webhook payload formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebhookFormat {
    Generic,
    Discord,
    Slack,
}

impl WebhookFormat {
    fn parse(raw: &str) -> Result<Self, ConfigError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "generic" => Ok(Self::Generic),
            "discord" => Ok(Self::Discord),
            "slack" => Ok(Self::Slack),
            other => Err(ConfigError::InvalidValue {
                var: "ALERT_WEBHOOK_FORMAT".to_owned(),
                reason: format!("unsupported value '{other}' (expected generic|discord|slack)"),
            }),
        }
    }
}

/// Configuration loading and validation errors (fail-fast on startup).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    /// A required environment variable is missing or empty.
    #[error("missing required environment variable: {0}")]
    MissingVar(String),

    /// An environment variable has an invalid format or fails a security policy.
    #[error("invalid environment variable {var}: {reason}")]
    InvalidValue { var: String, reason: String },

    /// Failed to construct the encryption key ring.
    #[error("invalid vault key configuration: {0}")]
    KeyRing(#[from] CryptoError),
}

/// Validated runtime configuration for `SecurityVault`.
///
/// Implements a custom `Debug` that redacts all secret values.
#[derive(Clone)]
pub struct AppConfig {
    pub app_env: AppEnv,
    pub port: u16,
    pub app_origin: String,
    pub allow_registration: bool,
    pub database_url: SecretString,
    pub key_ring: KeyRing,
    pub security_pepper: SecretString,
    pub alert_webhook_url: Option<SecretString>,
    pub alert_webhook_format: WebhookFormat,
    pub static_dir: Option<PathBuf>,
}

impl fmt::Debug for AppConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppConfig")
            .field("app_env", &self.app_env)
            .field("port", &self.port)
            .field("app_origin", &self.app_origin)
            .field("allow_registration", &self.allow_registration)
            .field("database_url", &"[REDACTED]")
            .field("key_ring", &self.key_ring)
            .field("security_pepper", &"[REDACTED]")
            .field(
                "alert_webhook_url",
                &self.alert_webhook_url.as_ref().map(|_| "[REDACTED]"),
            )
            .field("alert_webhook_format", &self.alert_webhook_format)
            .field("static_dir", &self.static_dir)
            .finish()
    }
}

impl AppConfig {
    /// Loads and validates configuration from process environment variables.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_pairs(std::env::vars())
    }

    /// Loads and validates configuration from any `(key, value)` iterator (ideal for unit tests).
    pub fn from_pairs<I, K, V>(pairs: I) -> Result<Self, ConfigError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let map: HashMap<String, String> = pairs
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();

        let app_env = match non_empty(&map, "APP_ENV") {
            Some(raw) => AppEnv::parse(raw)?,
            None => AppEnv::Development,
        };

        let port = match non_empty(&map, "PORT") {
            Some(raw) => {
                let parsed: u16 = raw.parse().map_err(|_| ConfigError::InvalidValue {
                    var: "PORT".to_owned(),
                    reason: "must be a valid TCP port (1..=65535)".to_owned(),
                })?;
                if parsed == 0 {
                    return Err(ConfigError::InvalidValue {
                        var: "PORT".to_owned(),
                        reason: "port must be >= 1".to_owned(),
                    });
                }
                parsed
            }
            None => 8080,
        };

        let app_origin = parse_app_origin(&map, app_env)?;
        let allow_registration = parse_bool(&map, "ALLOW_REGISTRATION", true)?;
        let database_url = parse_database_url(&map, app_env)?;
        let key_ring = parse_key_ring(&map)?;
        let security_pepper = parse_security_pepper(&map)?;
        let alert_webhook_url = parse_alert_webhook_url(&map, app_env)?;

        let alert_webhook_format = match non_empty(&map, "ALERT_WEBHOOK_FORMAT") {
            Some(raw) => WebhookFormat::parse(raw)?,
            None => WebhookFormat::Generic,
        };

        let static_dir = non_empty(&map, "STATIC_DIR").map(PathBuf::from);

        Ok(Self {
            app_env,
            port,
            app_origin,
            allow_registration,
            database_url,
            key_ring,
            security_pepper,
            alert_webhook_url,
            alert_webhook_format,
            static_dir,
        })
    }

    /// Returns the active encryption key version.
    #[must_use]
    pub const fn active_key_version(&self) -> i16 {
        self.key_ring.active_version()
    }
}

fn non_empty<'a>(map: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    map.get(key)
        .map(String::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn parse_bool(
    map: &HashMap<String, String>,
    var: &str,
    default: bool,
) -> Result<bool, ConfigError> {
    match non_empty(map, var) {
        None => Ok(default),
        Some(raw) => match raw.to_ascii_lowercase().as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(ConfigError::InvalidValue {
                var: var.to_owned(),
                reason: "must be 'true' or 'false'".to_owned(),
            }),
        },
    }
}

fn parse_app_origin(map: &HashMap<String, String>, app_env: AppEnv) -> Result<String, ConfigError> {
    let raw = match non_empty(map, "APP_ORIGIN") {
        Some(val) => val,
        None if app_env.is_production() => {
            return Err(ConfigError::MissingVar("APP_ORIGIN".to_owned()));
        }
        None => "http://localhost:5173",
    };

    let parsed = Url::parse(raw).map_err(|_| ConfigError::InvalidValue {
        var: "APP_ORIGIN".to_owned(),
        reason: "must be a valid URL".to_owned(),
    })?;

    if app_env.is_production() {
        if parsed.scheme() != "https" {
            return Err(ConfigError::InvalidValue {
                var: "APP_ORIGIN".to_owned(),
                reason: "must use https:// in production".to_owned(),
            });
        }
    } else if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(ConfigError::InvalidValue {
            var: "APP_ORIGIN".to_owned(),
            reason: "scheme must be http or https".to_owned(),
        });
    }

    if parsed.host_str().is_none() {
        return Err(ConfigError::InvalidValue {
            var: "APP_ORIGIN".to_owned(),
            reason: "must contain a host".to_owned(),
        });
    }

    Ok(raw.trim_end_matches('/').to_owned())
}

fn parse_database_url(
    map: &HashMap<String, String>,
    app_env: AppEnv,
) -> Result<SecretString, ConfigError> {
    let raw = non_empty(map, "DATABASE_URL")
        .ok_or_else(|| ConfigError::MissingVar("DATABASE_URL".to_owned()))?;

    let parsed = Url::parse(raw).map_err(|_| ConfigError::InvalidValue {
        var: "DATABASE_URL".to_owned(),
        reason: "must be a valid PostgreSQL connection URL".to_owned(),
    })?;

    if parsed.scheme() != "postgres" && parsed.scheme() != "postgresql" {
        return Err(ConfigError::InvalidValue {
            var: "DATABASE_URL".to_owned(),
            reason: "scheme must be postgres:// or postgresql://".to_owned(),
        });
    }

    if app_env.is_production() {
        let has_verify_full = parsed
            .query_pairs()
            .any(|(k, v)| k == "sslmode" && v == "verify-full");
        if !has_verify_full {
            return Err(ConfigError::InvalidValue {
                var: "DATABASE_URL".to_owned(),
                reason: "production requires sslmode=verify-full".to_owned(),
            });
        }
    }

    Ok(SecretString::from(raw.to_owned()))
}

fn parse_key_ring(map: &HashMap<String, String>) -> Result<KeyRing, ConfigError> {
    let active_raw = non_empty(map, "VAULT_ACTIVE_KEY_VERSION")
        .ok_or_else(|| ConfigError::MissingVar("VAULT_ACTIVE_KEY_VERSION".to_owned()))?;

    let active_version: i16 = active_raw.parse().map_err(|_| ConfigError::InvalidValue {
        var: "VAULT_ACTIVE_KEY_VERSION".to_owned(),
        reason: "must be an integer >= 1".to_owned(),
    })?;

    if active_version < 1 {
        return Err(ConfigError::InvalidValue {
            var: "VAULT_ACTIVE_KEY_VERSION".to_owned(),
            reason: "must be >= 1".to_owned(),
        });
    }

    let mut keys: HashMap<i16, Zeroizing<[u8; KEY_LEN]>> = HashMap::new();

    for (var_name, raw_value) in map {
        if let Some(suffix) = var_name.strip_prefix(VAULT_KEY_PREFIX) {
            let version: i16 = suffix.parse().map_err(|_| ConfigError::InvalidValue {
                var: var_name.clone(),
                reason: "suffix after VAULT_KEY_V must be an integer >= 1".to_owned(),
            })?;
            if version < 1 {
                return Err(ConfigError::InvalidValue {
                    var: var_name.clone(),
                    reason: "key version must be >= 1".to_owned(),
                });
            }
            let secret_hex = SecretString::from(raw_value.as_str());
            let decoded =
                KeyRing::decode_hex_key(&secret_hex).map_err(|_| ConfigError::InvalidValue {
                    var: var_name.clone(),
                    reason: "must be exactly 64 valid hexadecimal characters (32 bytes)".to_owned(),
                })?;
            keys.insert(version, decoded);
        }
    }

    if !keys.contains_key(&active_version) {
        return Err(ConfigError::MissingVar(format!(
            "{VAULT_KEY_PREFIX}{active_version}"
        )));
    }

    KeyRing::new(active_version, keys).map_err(ConfigError::from)
}

fn parse_security_pepper(map: &HashMap<String, String>) -> Result<SecretString, ConfigError> {
    let raw = non_empty(map, "SECURITY_PEPPER")
        .ok_or_else(|| ConfigError::MissingVar("SECURITY_PEPPER".to_owned()))?;

    if raw.chars().count() < MIN_SECURITY_PEPPER_LEN {
        return Err(ConfigError::InvalidValue {
            var: "SECURITY_PEPPER".to_owned(),
            reason: format!("must be at least {MIN_SECURITY_PEPPER_LEN} characters long"),
        });
    }

    let secret = SecretString::from(raw.to_owned());
    // Ensure ExposeSecret is exercised only internally if needed; keep length verified.
    debug_assert!(secret.expose_secret().chars().count() >= MIN_SECURITY_PEPPER_LEN);
    Ok(secret)
}

fn parse_alert_webhook_url(
    map: &HashMap<String, String>,
    app_env: AppEnv,
) -> Result<Option<SecretString>, ConfigError> {
    let Some(raw) = non_empty(map, "ALERT_WEBHOOK_URL") else {
        return Ok(None);
    };

    let parsed = Url::parse(raw).map_err(|_| ConfigError::InvalidValue {
        var: "ALERT_WEBHOOK_URL".to_owned(),
        reason: "must be a valid URL".to_owned(),
    })?;

    if app_env.is_production() {
        if parsed.scheme() != "https" {
            return Err(ConfigError::InvalidValue {
                var: "ALERT_WEBHOOK_URL".to_owned(),
                reason: "must use https:// in production".to_owned(),
            });
        }
    } else if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(ConfigError::InvalidValue {
            var: "ALERT_WEBHOOK_URL".to_owned(),
            reason: "scheme must be http or https".to_owned(),
        });
    }

    Ok(Some(SecretString::from(raw.to_owned())))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn valid_dev_env() -> HashMap<String, String> {
        HashMap::from([
            ("APP_ENV".to_owned(), "development".to_owned()),
            ("PORT".to_owned(), "8080".to_owned()),
            ("APP_ORIGIN".to_owned(), "http://localhost:5173".to_owned()),
            ("ALLOW_REGISTRATION".to_owned(), "true".to_owned()),
            (
                "DATABASE_URL".to_owned(),
                "postgresql://user:pass@localhost:5432/vault".to_owned(),
            ),
            ("VAULT_ACTIVE_KEY_VERSION".to_owned(), "1".to_owned()),
            ("VAULT_KEY_V1".to_owned(), "a".repeat(64)),
            ("SECURITY_PEPPER".to_owned(), "p".repeat(64)),
            (
                "ALERT_WEBHOOK_URL".to_owned(),
                "http://localhost:9000/hook".to_owned(),
            ),
            ("ALERT_WEBHOOK_FORMAT".to_owned(), "discord".to_owned()),
        ])
    }

    #[test]
    fn loads_valid_development_and_multi_key_config() {
        let mut env = valid_dev_env();
        env.insert("VAULT_KEY_V2".to_owned(), "b".repeat(64));
        env.insert("VAULT_ACTIVE_KEY_VERSION".to_owned(), "2".to_owned());

        let cfg = AppConfig::from_pairs(env).unwrap();
        assert_eq!(cfg.app_env, AppEnv::Development);
        assert_eq!(cfg.port, 8080);
        assert!(cfg.allow_registration);
        assert_eq!(cfg.active_key_version(), 2);
        assert!(cfg.key_ring.has_version(1));
        assert!(cfg.key_ring.has_version(2));
        assert_eq!(cfg.alert_webhook_format, WebhookFormat::Discord);
        assert!(cfg.alert_webhook_url.is_some());
    }

    #[test]
    fn debug_output_redacts_all_secrets() {
        let env = valid_dev_env();
        let cfg = AppConfig::from_pairs(env).unwrap();
        let debug_str = format!("{cfg:?}");

        assert!(debug_str.contains("database_url: \"[REDACTED]\""));
        assert!(debug_str.contains("security_pepper: \"[REDACTED]\""));
        assert!(debug_str.contains("alert_webhook_url: Some(\"[REDACTED]\")"));
        assert!(!debug_str.contains(&"a".repeat(64)));
        assert!(!debug_str.contains(&"p".repeat(64)));
        assert!(!debug_str.contains("user:pass"));
        assert!(!debug_str.contains("localhost:9000"));
    }

    #[test]
    fn production_enforces_verify_full_and_https() {
        let mut env = valid_dev_env();
        env.insert("APP_ENV".to_owned(), "production".to_owned());
        env.insert(
            "APP_ORIGIN".to_owned(),
            "https://securityvault.onrender.com".to_owned(),
        );
        env.insert(
            "ALERT_WEBHOOK_URL".to_owned(),
            "https://discord.com/api/webhooks/123/secret".to_owned(),
        );

        // Missing sslmode=verify-full must fail in production.
        let err = AppConfig::from_pairs(env.clone()).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { ref var, .. } if var == "DATABASE_URL"));

        // With sslmode=verify-full succeeds.
        env.insert(
            "DATABASE_URL".to_owned(),
            "postgresql://app:pw@ep-test.neon.tech/neondb?sslmode=verify-full".to_owned(),
        );
        let cfg = AppConfig::from_pairs(env.clone()).unwrap();
        assert!(cfg.app_env.is_production());

        // Plain http webhook in production must fail.
        env.insert(
            "ALERT_WEBHOOK_URL".to_owned(),
            "http://insecure.example.com/hook".to_owned(),
        );
        let err = AppConfig::from_pairs(env).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidValue { ref var, .. } if var == "ALERT_WEBHOOK_URL")
        );
    }

    #[test]
    fn rejects_short_pepper_bad_hex_and_missing_active_key() {
        let mut env = valid_dev_env();
        env.insert("SECURITY_PEPPER".to_owned(), "too-short".to_owned());
        let err = AppConfig::from_pairs(env).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidValue { ref var, .. } if var == "SECURITY_PEPPER")
        );

        let mut env = valid_dev_env();
        env.insert("VAULT_KEY_V1".to_owned(), "not-hex".to_owned());
        let err = AppConfig::from_pairs(env).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { ref var, .. } if var == "VAULT_KEY_V1"));

        let mut env = valid_dev_env();
        env.insert("VAULT_ACTIVE_KEY_VERSION".to_owned(), "2".to_owned());
        let err = AppConfig::from_pairs(env).unwrap_err();
        assert_eq!(err, ConfigError::MissingVar("VAULT_KEY_V2".to_owned()));
    }

    #[test]
    fn parses_optional_static_dir() {
        let mut env = valid_dev_env();
        let cfg_without = AppConfig::from_pairs(env.clone()).unwrap();
        assert!(cfg_without.static_dir.is_none());

        env.insert("STATIC_DIR".to_owned(), "  /app/static  ".to_owned());
        let cfg_with = AppConfig::from_pairs(env).unwrap();
        assert_eq!(cfg_with.static_dir, Some(PathBuf::from("/app/static")));
    }
}
