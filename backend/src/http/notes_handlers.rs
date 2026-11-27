//! HTTP handlers for `/api/v1/notes/*` aligned with `contrato-api.md`.

use std::str::FromStr;

use axum::{
    Json,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::{
    error::AppError,
    models::{ApiSuccess, ApiSuccessWithMeta, NoteCategory},
};
use crate::http::{
    AppState,
    auth_handlers::{require_mfa_session, require_mfa_session_with_csrf},
    middleware::{RequestMeta, ValidatedJson},
};
use crate::services::notes::{DEFAULT_LIMIT, DEFAULT_PAGE};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateNoteRequest {
    pub title: String,
    pub content: String,
    pub category: NoteCategory,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateNoteRequest {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub category: Option<NoteCategory>,
}

#[derive(Debug, Serialize)]
struct DeleteNoteData {
    deleted: bool,
}

/// `GET /api/v1/notes`
pub async fn list_notes(
    State(state): State<AppState>,
    Extension(meta): Extension<RequestMeta>,
    headers: HeaderMap,
    Query(params): Query<Vec<(String, String)>>,
) -> Result<Response, AppError> {
    let auth_session = require_mfa_session(&state, &headers).await?;
    let (page, limit, category) = parse_list_query(&params)?;

    let (items, pagination) = state
        .notes
        .list_notes(
            auth_session.session.user_id,
            category,
            page,
            limit,
            &meta.client_ip,
            &meta.request_id,
        )
        .await?;

    Ok((
        StatusCode::OK,
        Json(ApiSuccessWithMeta::new(items, pagination)),
    )
        .into_response())
}

/// `POST /api/v1/notes`
pub async fn create_note(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedJson(payload): ValidatedJson<CreateNoteRequest>,
) -> Result<Response, AppError> {
    let auth_session = require_mfa_session_with_csrf(&state, &headers).await?;

    let created = state
        .notes
        .create_note(
            auth_session.session.user_id,
            &payload.title,
            &payload.content,
            payload.category,
        )
        .await?;

    Ok((StatusCode::CREATED, Json(ApiSuccess::new(created))).into_response())
}

/// `GET /api/v1/notes/{id}`
pub async fn get_note(
    State(state): State<AppState>,
    Extension(meta): Extension<RequestMeta>,
    headers: HeaderMap,
    Path(raw_id): Path<String>,
) -> Result<Response, AppError> {
    let auth_session = require_mfa_session(&state, &headers).await?;
    let note_id = parse_uuid(&raw_id)?;

    let note = state
        .notes
        .get_note(
            auth_session.session.user_id,
            note_id,
            &meta.client_ip,
            &meta.request_id,
        )
        .await?;

    Ok((StatusCode::OK, Json(ApiSuccess::new(note))).into_response())
}

/// `PATCH /api/v1/notes/{id}`
pub async fn update_note(
    State(state): State<AppState>,
    Extension(meta): Extension<RequestMeta>,
    headers: HeaderMap,
    Path(raw_id): Path<String>,
    ValidatedJson(payload): ValidatedJson<UpdateNoteRequest>,
) -> Result<Response, AppError> {
    let auth_session = require_mfa_session_with_csrf(&state, &headers).await?;
    let note_id = parse_uuid(&raw_id)?;

    let updated = state
        .notes
        .update_note(
            auth_session.session.user_id,
            note_id,
            payload.title.as_deref(),
            payload.content.as_deref(),
            payload.category,
            &meta.client_ip,
            &meta.request_id,
        )
        .await?;

    Ok((StatusCode::OK, Json(ApiSuccess::new(updated))).into_response())
}

/// `DELETE /api/v1/notes/{id}`
pub async fn delete_note(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_id): Path<String>,
) -> Result<Response, AppError> {
    let auth_session = require_mfa_session_with_csrf(&state, &headers).await?;
    let note_id = parse_uuid(&raw_id)?;

    state
        .notes
        .delete_note(auth_session.session.user_id, note_id)
        .await?;

    Ok((
        StatusCode::OK,
        Json(ApiSuccess::new(DeleteNoteData { deleted: true })),
    )
        .into_response())
}

fn parse_uuid(raw: &str) -> Result<Uuid, AppError> {
    Uuid::parse_str(raw.trim()).map_err(|_| AppError::validation("Identificador UUID inválido"))
}

fn parse_list_query(
    params: &[(String, String)],
) -> Result<(u32, u32, Option<NoteCategory>), AppError> {
    let mut page = DEFAULT_PAGE;
    let mut limit = DEFAULT_LIMIT;
    let mut category: Option<NoteCategory> = None;

    for (key, value) in params {
        match key.as_str() {
            "page" => {
                page = value.trim().parse::<u32>().map_err(|_| {
                    AppError::validation("El parámetro 'page' debe ser un entero positivo")
                })?;
            }
            "limit" => {
                limit = value.trim().parse::<u32>().map_err(|_| {
                    AppError::validation("El parámetro 'limit' debe ser un entero positivo")
                })?;
            }
            "category" => {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    category = None;
                } else {
                    category = Some(
                        NoteCategory::from_str(trimmed)
                            .map_err(|_| AppError::validation("Categoría de nota inválida"))?,
                    );
                }
            }
            other => {
                return Err(AppError::validation(format!(
                    "Parámetro de consulta no permitido: '{other}'"
                )));
            }
        }
    }

    Ok((page, limit, category))
}
