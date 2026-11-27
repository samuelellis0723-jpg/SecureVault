//! `SecurityVault` HTTP server binary with graceful shutdown (`SIGINT` / `SIGTERM`).

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;

use tokio::net::TcpListener;
use tracing_subscriber::{EnvFilter, fmt};

use security_vault_backend::{
    config::AppConfig,
    http::{AppState, build_router},
    repositories::{VaultRepositories, pg::PgStore},
    services::alerts::AlertService,
};

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();

    if let Err(err) = run().await {
        tracing::error!(error = %err, "securityvault server terminated with error");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,sqlx::query=warn"));
    let _ = fmt().with_env_filter(filter).json().try_init();
}

async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = AppConfig::from_env()?;
    tracing::info!(
        app_env = ?config.app_env,
        port = config.port,
        active_key_version = config.active_key_version(),
        allow_registration = config.allow_registration,
        static_dir_configured = config.static_dir.is_some(),
        "configuration loaded"
    );

    let pg_store = PgStore::connect(&config.database_url, config.app_env.is_production()).await?;
    let repos = VaultRepositories::from_pg(Arc::new(pg_store));

    let alerts = AlertService::from_webhook_config(
        config.alert_webhook_url.clone(),
        config.alert_webhook_format,
        config.security_pepper.clone(),
    );

    let state = AppState::new(&config, repos, alerts);
    let router = build_router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(bind_addr = %addr, "securityvault HTTP server listening");

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    tracing::info!("securityvault HTTP server stopped gracefully");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {
            tracing::info!("received SIGINT, initiating graceful shutdown");
        }
        () = terminate => {
            tracing::info!("received SIGTERM, initiating graceful shutdown");
        }
    }
}
