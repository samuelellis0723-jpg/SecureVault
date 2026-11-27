//! Axum HTTP router, shared `AppState`, handlers, and security middleware stack.

pub mod auth_handlers;
pub mod health;
pub mod middleware;
pub mod notes_handlers;

use std::path::PathBuf;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::StatusCode,
    middleware as axum_mw,
    routing::{any, get, post},
};
use tower_http::{
    services::{ServeDir, ServeFile},
    timeout::TimeoutLayer,
};

use crate::config::{AppConfig, AppEnv};
use crate::domain::error::AppError;
use crate::http::middleware::{
    API_BODY_LIMIT_BYTES, API_REQUEST_TIMEOUT, IpRateLimiter, RateLimitConfig, build_cors_layer,
    rate_limit_middleware, security_headers_and_observability,
};
use crate::repositories::VaultRepositories;
use crate::services::{alerts::AlertService, auth::AuthService, notes::NotesService};

/// Shared application state injected into Axum handlers and middlewares.
#[derive(Clone)]
pub struct AppState {
    pub auth: AuthService,
    pub notes: NotesService,
    pub alerts: AlertService,
    pub app_env: AppEnv,
    pub app_origin: String,
    pub static_dir: Option<PathBuf>,
    pub rate_limiter: IpRateLimiter,
}

impl AppState {
    /// Builds [`AppState`] with default per-IP rate limits.
    #[must_use]
    pub fn new(config: &AppConfig, repos: VaultRepositories, alerts: AlertService) -> Self {
        Self::with_rate_limits(config, repos, alerts, RateLimitConfig::default())
    }

    /// Builds [`AppState`] with custom per-IP rate limits (useful for tests).
    #[must_use]
    pub fn with_rate_limits(
        config: &AppConfig,
        repos: VaultRepositories,
        alerts: AlertService,
        rate_limit_config: RateLimitConfig,
    ) -> Self {
        let auth = AuthService::new(
            repos.clone(),
            config.key_ring.clone(),
            config.security_pepper.clone(),
            config.allow_registration,
            alerts.clone(),
        );
        let notes = NotesService::new(repos, config.key_ring.clone(), alerts.clone());

        Self {
            auth,
            notes,
            alerts,
            app_env: config.app_env,
            app_origin: config.app_origin.clone(),
            static_dir: config.static_dir.clone(),
            rate_limiter: IpRateLimiter::new(rate_limit_config),
        }
    }
}

async fn api_not_found() -> AppError {
    AppError::NotFound
}

/// Builds the hardened Axum [`Router`] exposing `/healthz`, `/api/v1/*`, and optional SPA static
/// assets when `STATIC_DIR` is configured and exists on disk.
pub fn build_router(state: AppState) -> Router {
    let cors = build_cors_layer(&state.app_origin);

    let api_v1 = Router::new()
        .route("/auth/register", post(auth_handlers::register))
        .route("/auth/totp/confirm", post(auth_handlers::confirm_totp))
        .route("/auth/login", post(auth_handlers::login))
        .route("/auth/totp/verify", post(auth_handlers::verify_totp))
        .route("/auth/logout", post(auth_handlers::logout))
        .route("/auth/me", get(auth_handlers::me))
        .route(
            "/notes",
            get(notes_handlers::list_notes).post(notes_handlers::create_note),
        )
        .route(
            "/notes/{id}",
            get(notes_handlers::get_note)
                .patch(notes_handlers::update_note)
                .delete(notes_handlers::delete_note),
        )
        .fallback(api_not_found)
        .layer(DefaultBodyLimit::max(API_BODY_LIMIT_BYTES))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            API_REQUEST_TIMEOUT,
        ))
        .layer(axum_mw::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .layer(cors);

    let mut router = Router::new()
        .route("/healthz", get(health::healthz))
        .nest("/api/v1", api_v1)
        .route("/api", any(api_not_found))
        .route("/api/{*rest}", any(api_not_found));

    if let Some(dir) = state.static_dir.as_ref().filter(|path| path.is_dir()) {
        let spa_service = ServeDir::new(dir).fallback(ServeFile::new(dir.join("index.html")));
        router = router.fallback_service(spa_service);
    }

    router
        .layer(axum_mw::from_fn_with_state(
            state.clone(),
            security_headers_and_observability,
        ))
        .with_state(state)
}
