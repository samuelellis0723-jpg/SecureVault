//! `SecurityVault` backend library.
//!
//! Provides fail-fast configuration loading, domain models and safe HTTP errors,
//! cryptographic primitives (Argon2id, AES-256-GCM with versioned `KeyRing`,
//! and RFC 6238 TOTP + recovery codes), persistence repositories (`memory` and `pg`),
//! business services (`auth`, `notes`, `alerts`, `rotation`), and the Axum HTTP router.

pub mod config;
pub mod crypto;
pub mod domain;
pub mod http;
pub mod repositories;
pub mod services;
