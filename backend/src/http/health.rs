//! Public healthcheck endpoint (`GET /healthz`).

use axum::{Json, http::StatusCode, response::IntoResponse};
use serde::Serialize;

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

/// Returns `200 OK` with `{ "status": "ok" }` without exposing internal dependency details.
pub async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, Json(HealthResponse { status: "ok" }))
}
