//! HTTP handlers for `/api/v1/auth/*` aligned with `contrato-api.md`.

use axum::{
    Json,
    body::Bytes,
    extract::{Extension, State},
    http::{HeaderMap, StatusCode, header::SET_COOKIE},
    response::{IntoResponse, Response},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::domain::{
    error::AppError,
    models::{ApiSuccess, UserPublic},
};
use crate::http::{
    AppState,
    middleware::{
        RequestMeta, ValidatedJson, build_clear_session_cookie, build_session_cookie,
        extract_csrf_header, extract_session_cookie,
    },
};
use crate::services::auth::AuthenticatedSession;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
struct AuthSessionData {
    user: UserPublic,
    csrf_token: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyLogoutBody {}

#[derive(Debug, Serialize)]
struct LogoutData {
    logged_out: bool,
}

/// `POST /api/v1/auth/register`
pub async fn register(
    State(state): State<AppState>,
    ValidatedJson(payload): ValidatedJson<RegisterRequest>,
) -> Result<Response, AppError> {
    let out = state
        .auth
        .register(&payload.email, SecretString::from(payload.password))
        .await?;

    let cookie = build_session_cookie(
        out.session_token.expose_secret(),
        out.session_max_age_secs,
        state.app_env.is_production(),
    )?;

    let body = ApiSuccess::new(AuthSessionData {
        user: out.user,
        csrf_token: out.csrf_token,
    });

    let mut response = (StatusCode::CREATED, Json(body)).into_response();
    response.headers_mut().append(SET_COOKIE, cookie);
    Ok(response)
}

/// `POST /api/v1/auth/login`
pub async fn login(
    State(state): State<AppState>,
    Extension(meta): Extension<RequestMeta>,
    ValidatedJson(payload): ValidatedJson<LoginRequest>,
) -> Result<Response, AppError> {
    let out = state
        .auth
        .login(
            &payload.email,
            SecretString::from(payload.password),
            &meta.client_ip,
            &meta.request_id,
        )
        .await?;

    let cookie = build_session_cookie(
        out.session_token.expose_secret(),
        out.session_max_age_secs,
        state.app_env.is_production(),
    )?;

    let body = ApiSuccess::new(AuthSessionData {
        user: out.user,
        csrf_token: out.csrf_token,
    });

    let mut response = (StatusCode::OK, Json(body)).into_response();
    response.headers_mut().append(SET_COOKIE, cookie);
    Ok(response)
}

/// `POST /api/v1/auth/logout`
pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    if !body.is_empty() {
        let _: EmptyLogoutBody = serde_json::from_slice(&body)
            .map_err(|_| AppError::validation("El cuerpo de logout debe estar vacío o ser {}"))?;
    }

    let auth_session = require_session_with_csrf(&state, &headers).await?;
    state.auth.logout(&auth_session).await?;

    let clear_cookie = build_clear_session_cookie(state.app_env.is_production())?;
    let mut response = (
        StatusCode::OK,
        Json(ApiSuccess::new(LogoutData { logged_out: true })),
    )
        .into_response();
    response.headers_mut().append(SET_COOKIE, clear_cookie);
    Ok(response)
}

/// `GET /api/v1/auth/me`
pub async fn me(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, AppError> {
    let auth_session = require_session(&state, &headers).await?;
    let out = state.auth.me(&auth_session).await?;
    Ok((StatusCode::OK, Json(ApiSuccess::new(out))).into_response())
}

pub(crate) async fn require_session(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedSession, AppError> {
    let raw_token = extract_session_cookie(headers)
        .ok_or_else(|| AppError::Unauthorized("Sesión requerida".to_owned()))?;
    state.auth.authenticate_session(&raw_token).await
}

pub(crate) async fn require_session_with_csrf(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedSession, AppError> {
    let auth_session = require_session(state, headers).await?;
    state
        .auth
        .verify_csrf(&auth_session.session, extract_csrf_header(headers))?;
    Ok(auth_session)
}
