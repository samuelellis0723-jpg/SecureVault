//! Database migration CLI applying `backend/migrations` via `SQLx` without logging credentials.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use sqlx::{
    migrate::Migrator,
    postgres::{PgConnectOptions, PgPoolOptions},
};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => {
            println!("SecurityVault migrations applied successfully.");
            ExitCode::SUCCESS
        }
        Err(msg) => {
            eprintln!("Migration error: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn resolve_migrations_dir() -> Result<PathBuf, String> {
    if let Ok(explicit) = std::env::var("MIGRATIONS_DIR") {
        let path = PathBuf::from(explicit);
        if path.is_dir() {
            return Ok(path);
        }
    }

    let candidates = [
        Path::new("./migrations"),
        Path::new("./backend/migrations"),
        Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")),
    ];

    for candidate in candidates {
        if candidate.is_dir() {
            return Ok(candidate.to_path_buf());
        }
    }

    Err("could not locate migrations directory (set MIGRATIONS_DIR)".to_owned())
}

async fn run() -> Result<(), String> {
    let raw_url = std::env::var("DATABASE_URL")
        .map_err(|_| "missing required environment variable DATABASE_URL".to_owned())?;
    if raw_url.trim().is_empty() {
        return Err("DATABASE_URL cannot be empty".to_owned());
    }
    let database_url = SecretString::from(raw_url);

    let migrations_dir = resolve_migrations_dir()?;
    let migrator = Migrator::new(migrations_dir)
        .await
        .map_err(|err| format!("failed to load migrations: {err}"))?;

    let options = PgConnectOptions::from_str(database_url.expose_secret())
        .map_err(|_| "invalid DATABASE_URL format".to_owned())?;

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(options)
        .await
        .map_err(|_| "failed to connect to PostgreSQL (check DATABASE_URL and TLS)".to_owned())?;

    migrator
        .run(&pool)
        .await
        .map_err(|err| format!("sqlx migration failed: {err}"))?;

    pool.close().await;
    Ok(())
}
