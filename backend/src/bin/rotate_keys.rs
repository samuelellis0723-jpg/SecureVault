//! Idempotent key-rotation CLI re-encrypting legacy `notes` and `users` TOTP secrets
//! to `VAULT_ACTIVE_KEY_VERSION` without ever logging sensitive material.

use std::process::ExitCode;
use std::sync::Arc;

use security_vault_backend::{
    config::AppConfig,
    repositories::{VaultRepositories, pg::PgStore},
    services::rotation::{DEFAULT_ROTATION_BATCH_SIZE, rotate_all_keys},
};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("Key rotation failed: {msg}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let config = AppConfig::from_env().map_err(|err| format!("configuration error: {err}"))?;
    let pg_store = PgStore::connect(&config.database_url, config.app_env.is_production())
        .await
        .map_err(|err| format!("database connection error: {err}"))?;

    let repos = VaultRepositories::from_pg(Arc::new(pg_store));
    let report = rotate_all_keys(&repos, &config.key_ring, DEFAULT_ROTATION_BATCH_SIZE)
        .await
        .map_err(|err| format!("rotation error: {err}"))?;

    println!(
        "Key rotation complete: active_key_version={}, notes_rotated={}, users_rotated={}",
        report.active_version, report.notes_rotated, report.users_rotated
    );
    Ok(())
}
