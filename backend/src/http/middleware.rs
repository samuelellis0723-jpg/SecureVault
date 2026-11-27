//! HTTP middlewares, strict JSON extraction, cookies, CORS, security headers, and rate limiting.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    Json,
    body::Body,
    extract::{ConnectInfo, FromRequest, Request, State, rejection::JsonRejection},
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode,
        header::{self, CACHE_CONTROL, CONTENT_TYPE, COOKIE},
    },
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::de::DeserializeOwned;
use tokio::sync::Mutex;
use tower_http::cors::{AllowOrigin, CorsLayer};
use uuid::Uuid;

use crate::domain::error::{AppError, ErrorBody, ErrorEnvelope, IsCryptoIntegrityError};
use crate::http::AppState;
use crate::services::alerts::AlertEventKind;

/// Name of the `HttpOnly` session cookie.
pub const SESSION_COOKIE_NAME: &str = "sv_session";

/// Name of the mandatory CSRF header for authenticated mutations.
pub const CSRF_HEADER_NAME: &str = "x-csrf-token";

/// Name of the correlation request identifier header.
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Maximum request payload size on `/api/v1` routes (64 KiB).
pub const API_BODY_LIMIT_BYTES: usize = 64 * 1024;

/// Maximum per-request timeout on `/api/v1` routes.
pub const API_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Strict Content-Security-Policy matching `contrato-api.md`.
pub const STRICT_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";

/// Strict-Transport-Security header emitted in production.
pub const STRICT_HSTS: &str = "max-age=31536000; includeSubDomains";

/// Maximum number of distinct IP buckets kept in memory to prevent unbounded growth.
const MAX_RATE_LIMIT_ENTRIES: usize = 10_000;

/// Per-request metadata injected by the outer middleware.
#[derive(Debug, Clone)]
pub struct RequestMeta {
    pub request_id: String,
    pub client_ip: String,
}

/// Configurable rate-limit thresholds per IP window.
#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    pub auth_max_requests: u32,
    pub api_max_requests: u32,
    pub window: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            auth_max_requests: 30,
            api_max_requests: 120,
            window: Duration::from_secs(60),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct WindowEntry {
    count: u32,
    window_start: Instant,
}

/// Bounded in-memory fixed-window rate limiter keyed by `(bucket, client_ip)`.
#[derive(Clone)]
pub struct IpRateLimiter {
    config: RateLimitConfig,
    entries: Arc<Mutex<HashMap<(u8, String), WindowEntry>>>,
}

impl IpRateLimiter {
    /// Creates a new [`IpRateLimiter`] with the provided configuration.
    #[must_use]
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Checks and increments the rate counter for `client_ip` in either the auth or general bucket.
    /// Returns `Ok(())` when allowed or `Err(AppError::RateLimited)` when exceeded.
    pub async fn check(&self, client_ip: &str, is_auth_route: bool) -> Result<(), AppError> {
        let now = Instant::now();
        let bucket = u8::from(is_auth_route);
        let limit = if is_auth_route {
            self.config.auth_max_requests
        } else {
            self.config.api_max_requests
        };
        let window = self.config.window;

        let mut map = self.entries.lock().await;

        if map.len() >= MAX_RATE_LIMIT_ENTRIES {
            map.retain(|_, entry| now.duration_since(entry.window_start) < window);
            if map.len() >= MAX_RATE_LIMIT_ENTRIES {
                // Evict only the oldest 20% of entries so active attacker counters are preserved.
                let evict_count = (MAX_RATE_LIMIT_ENTRIES / 5).max(1);
                let mut oldest: Vec<((u8, String), Instant)> = map
                    .iter()
                    .map(|(k, v)| (k.clone(), v.window_start))
                    .collect();
                oldest.sort_by_key(|(_, started_at)| *started_at);
                for (key, _) in oldest.into_iter().take(evict_count) {
                    map.remove(&key);
                }
            }
        }

        let key = (bucket, client_ip.to_owned());
        let entry = map.entry(key).or_insert(WindowEntry {
            count: 0,
            window_start: now,
        });

        if now.duration_since(entry.window_start) >= window {
            entry.count = 0;
            entry.window_start = now;
        }

        if entry.count >= limit {
            return Err(AppError::RateLimited);
        }

        entry.count = entry.count.saturating_add(1);
        Ok(())
    }
}

/// Builds a strict CORS layer allowing only `app_origin` with credentials enabled.
pub fn build_cors_layer(app_origin: &str) -> CorsLayer {
    let origin = HeaderValue::from_str(app_origin)
        .unwrap_or_else(|_| HeaderValue::from_static("http://localhost:5173"));

    CorsLayer::new()
        .allow_origin(AllowOrigin::exact(origin))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([CONTENT_TYPE, HeaderName::from_static(CSRF_HEADER_NAME)])
        .allow_credentials(true)
        .max_age(Duration::from_secs(600))
}

fn parse_valid_ip(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return None;
    }
    trimmed
        .parse::<std::net::IpAddr>()
        .ok()
        .map(|ip| ip.to_string())
}

/// Extracts a trustworthy client IP from trusted edge headers (`True-Client-IP`,
/// `CF-Connecting-IP`), the rightmost entry of `X-Forwarded-For` appended by the
/// trusted Render reverse proxy (preventing left-side header spoofing), or
/// `ConnectInfo<SocketAddr>`, falling back to `"127.0.0.1"`.
#[must_use]
pub fn extract_client_ip(req: &Request) -> String {
    for header_name in ["true-client-ip", "cf-connecting-ip"] {
        if let Some(value) = req.headers().get(header_name).and_then(|v| v.to_str().ok())
            && let Some(ip) = parse_valid_ip(value)
        {
            return ip;
        }
    }

    if let Some(xff) = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        && let Some(rightmost) = xff.rsplit(',').next()
        && let Some(ip) = parse_valid_ip(rightmost)
    {
        return ip;
    }

    if let Some(ConnectInfo(addr)) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
        return addr.ip().to_string();
    }

    "127.0.0.1".to_owned()
}

/// Outer middleware that attaches `RequestMeta`, applies mandatory OWASP security headers
/// to every response, sets `Cache-Control: no-store` on `/api/v1/*`, and dispatches
/// non-blocking `http_5xx` webhook alerts on unhandled server errors.
pub async fn security_headers_and_observability(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let request_id = Uuid::new_v4().to_string();
    let client_ip = extract_client_ip(&req);
    let path = req.uri().path();
    let is_api_path = path == "/api/v1" || path.starts_with("/api/v1/");
    let is_hashed_asset = path.starts_with("/assets/");

    req.extensions_mut().insert(RequestMeta {
        request_id: request_id.clone(),
        client_ip: client_ip.clone(),
    });

    let mut response = next.run(req).await;

    if response.status().is_server_error()
        && response
            .extensions()
            .get::<IsCryptoIntegrityError>()
            .is_none()
    {
        state.alerts.notify(
            AlertEventKind::Http5xx,
            &request_id,
            &client_ip,
            "INTERNAL_ERROR",
        );
    }

    let is_success = response.status().is_success();
    let headers = response.headers_mut();
    let is_html = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("text/html"));

    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(STRICT_CSP),
    );
    if state.app_env.is_production() {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static(STRICT_HSTS),
        );
    }
    if is_api_path {
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    } else if is_hashed_asset && is_success && !is_html {
        headers.insert(
            CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=31536000, immutable"),
        );
    }
    if let Ok(req_id_val) = HeaderValue::from_str(&request_id) {
        headers.insert(HeaderName::from_static(REQUEST_ID_HEADER), req_id_val);
    }

    response
}

/// Per-IP rate limiting middleware applied to `/api/v1/*` routes.
pub async fn rate_limit_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    if req.method() == Method::OPTIONS {
        return next.run(req).await;
    }

    let client_ip = req
        .extensions()
        .get::<RequestMeta>()
        .map_or_else(|| extract_client_ip(&req), |m| m.client_ip.clone());

    let path = req.uri().path();
    let is_auth_route = path.starts_with("/auth") || path.starts_with("/api/v1/auth");

    if let Err(err) = state.rate_limiter.check(&client_ip, is_auth_route).await {
        return err.into_response();
    }

    next.run(req).await
}

/// Extracts the `sv_session` cookie value from request headers.
#[must_use]
pub fn extract_session_cookie(headers: &HeaderMap) -> Option<String> {
    for raw_header in headers.get_all(COOKIE) {
        let Ok(cookie_str) = raw_header.to_str() else {
            continue;
        };
        for part in cookie_str.split(';') {
            let trimmed = part.trim();
            if let Some((name, value)) = trimmed.split_once('=')
                && name.trim() == SESSION_COOKIE_NAME
            {
                let clean = value.trim();
                if !clean.is_empty() {
                    return Some(clean.to_owned());
                }
            }
        }
    }
    None
}

/// Extracts the `X-CSRF-Token` header value from request headers.
#[must_use]
pub fn extract_csrf_header(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(CSRF_HEADER_NAME)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Builds the `Set-Cookie` header value for an active `sv_session` cookie.
pub fn build_session_cookie(
    token: &str,
    max_age_secs: i64,
    is_production: bool,
) -> Result<HeaderValue, AppError> {
    let secure_attr = if is_production { "; Secure" } else { "" };
    let cookie = format!(
        "{SESSION_COOKIE_NAME}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age_secs}{secure_attr}"
    );
    HeaderValue::from_str(&cookie)
        .map_err(|_| AppError::Internal("failed to format session cookie header".to_owned()))
}

/// Builds the `Set-Cookie` header value that immediately expires `sv_session`.
pub fn build_clear_session_cookie(is_production: bool) -> Result<HeaderValue, AppError> {
    let secure_attr = if is_production { "; Secure" } else { "" };
    let cookie = format!(
        "{SESSION_COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0{secure_attr}"
    );
    HeaderValue::from_str(&cookie)
        .map_err(|_| AppError::Internal("failed to format clear-cookie header".to_owned()))
}

/// Strict JSON extractor that converts deserialization/unknown-field/syntax rejections into
/// the contract-standard `400 VALIDATION_ERROR` JSON envelope (preserving `413` on body limit).
pub struct ValidatedJson<T>(pub T);

impl<S, T> FromRequest<S> for ValidatedJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request<Body>, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) => Err(map_json_rejection(&rejection)),
        }
    }
}

fn map_json_rejection(rejection: &JsonRejection) -> Response {
    if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        let envelope = ErrorEnvelope {
            success: false,
            error: ErrorBody {
                code: "PAYLOAD_TOO_LARGE",
                message: "El cuerpo de la solicitud supera el límite permitido".to_owned(),
                details: None,
            },
        };
        return (StatusCode::PAYLOAD_TOO_LARGE, Json(envelope)).into_response();
    }

    let message = match rejection {
        JsonRejection::MissingJsonContentType(_) => {
            "La cabecera Content-Type debe ser application/json".to_owned()
        }
        JsonRejection::JsonSyntaxError(_) => "El cuerpo JSON tiene sintaxis inválida".to_owned(),
        JsonRejection::JsonDataError(_) => {
            "El cuerpo JSON contiene campos faltantes, inválidos o no permitidos".to_owned()
        }
        _ => "Cuerpo de solicitud JSON inválido".to_owned(),
    };

    AppError::validation(message).into_response()
}
