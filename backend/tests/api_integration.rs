//! End-to-end HTTP integration tests against the real Axum router using `tower::ServiceExt::oneshot`
//! and `InMemoryStore`, covering acceptance criteria CA-01 through CA-09.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header},
};
use secrecy::SecretString;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tower::ServiceExt;
use uuid::Uuid;
use zeroize::Zeroizing;

use security_vault_backend::{
    config::{AppConfig, AppEnv, WebhookFormat},
    crypto::cipher::{KEY_LEN, KeyRing},
    http::{AppState, build_router, middleware::RateLimitConfig},
    repositories::{VaultRepositories, memory::InMemoryStore},
    services::{
        alerts::{AlertService, HttpWebhookSink, RecordingAlertSink},
        rotation::rotate_all_keys,
    },
};

fn test_pepper() -> SecretString {
    SecretString::from("integration-test-security-pepper-minimum-32-chars-ok")
}

fn make_key_ring(active_version: i16, versions: &[(i16, u8)]) -> KeyRing {
    let mut keys = HashMap::new();
    for &(ver, byte) in versions {
        keys.insert(ver, Zeroizing::new([byte; KEY_LEN]));
    }
    KeyRing::new(active_version, keys).unwrap()
}

fn make_config(app_env: AppEnv, allow_registration: bool, key_ring: KeyRing) -> AppConfig {
    AppConfig {
        app_env,
        port: 8080,
        app_origin: if app_env.is_production() {
            "https://securityvault.onrender.com".to_owned()
        } else {
            "http://localhost:5173".to_owned()
        },
        allow_registration,
        database_url: SecretString::from("postgresql://user:pass@localhost:5432/vault"),
        key_ring,
        security_pepper: test_pepper(),
        alert_webhook_url: None,
        alert_webhook_format: WebhookFormat::Generic,
        static_dir: None,
    }
}

struct TestHarness {
    router: Router,
    store: Arc<InMemoryStore>,
    alerts_sink: Arc<RecordingAlertSink>,
}

impl TestHarness {
    fn new() -> Self {
        Self::with_options(
            AppEnv::Development,
            true,
            make_key_ring(1, &[(1, 0x11)]),
            RateLimitConfig {
                auth_max_requests: 200,
                api_max_requests: 200,
                window: Duration::from_secs(60),
            },
        )
    }

    fn with_options(
        app_env: AppEnv,
        allow_registration: bool,
        key_ring: KeyRing,
        rate_limits: RateLimitConfig,
    ) -> Self {
        let store = Arc::new(InMemoryStore::new());
        let repos = VaultRepositories::from_in_memory(Arc::clone(&store));
        let alerts_sink = Arc::new(RecordingAlertSink::new());
        let alerts = AlertService::spawn(Arc::clone(&alerts_sink) as _, test_pepper());
        let config = make_config(app_env, allow_registration, key_ring);
        let state = AppState::with_rate_limits(&config, repos, alerts, rate_limits);
        let router = build_router(state);

        Self {
            router,
            store,
            alerts_sink,
        }
    }
}

async fn send_json(
    router: &Router,
    method: Method,
    uri: &str,
    cookie: Option<&str>,
    csrf: Option<&str>,
    ip: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, HeaderMap, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(c) = cookie {
        builder = builder.header(header::COOKIE, format!("sv_session={c}"));
    }
    if let Some(token) = csrf {
        builder = builder.header("x-csrf-token", token);
    }
    if let Some(client_ip) = ip {
        builder = builder.header("x-forwarded-for", client_ip);
    }

    let request = match body {
        Some(json_val) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&json_val).unwrap()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };

    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let parsed = serde_json::from_slice(&bytes).unwrap_or_else(|_| json!({}));
    (status, headers, parsed)
}

fn extract_cookie_value(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::SET_COOKIE)?.to_str().ok()?;
    let pair = raw.split(';').next()?.trim();
    let (name, value) = pair.split_once('=')?;
    if name == "sv_session" {
        Some(value.to_owned())
    } else {
        None
    }
}

struct RegisteredUser {
    user_id: Uuid,
    cookie: String,
    csrf_token: String,
}

async fn register_user(router: &Router, email: &str, password: &str) -> RegisteredUser {
    let (status, headers, reg_body) = send_json(
        router,
        Method::POST,
        "/api/v1/auth/register",
        None,
        None,
        Some("198.51.100.10"),
        Some(json!({ "email": email, "password": password })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let cookie = extract_cookie_value(&headers).unwrap();
    let csrf_token = reg_body["data"]["csrf_token"].as_str().unwrap().to_owned();
    let user_id = Uuid::parse_str(reg_body["data"]["user"]["id"].as_str().unwrap()).unwrap();

    RegisteredUser {
        user_id,
        cookie,
        csrf_token,
    }
}

#[tokio::test]
async fn ca01_auth_register_and_direct_vault_lifecycle() {
    let harness = TestHarness::new();

    // 1. Register creates an immediately authenticated full session
    let (status, headers, reg_body) = send_json(
        &harness.router,
        Method::POST,
        "/api/v1/auth/register",
        None,
        None,
        Some("198.51.100.1"),
        Some(json!({
            "email": "  Alice@Example.COM ",
            "password": "StrongVaultPassword#2026"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(reg_body["success"], true);
    assert_eq!(reg_body["data"]["user"]["email"], "alice@example.com");
    assert!(reg_body["data"]["user"]["id"].as_str().is_some());
    assert!(reg_body["data"].get("totp").is_none());

    let set_cookie = headers
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Strict"));
    assert!(set_cookie.contains("Path=/"));
    assert!(set_cookie.contains("Max-Age=28800"));

    let full_cookie = extract_cookie_value(&headers).unwrap();
    let full_csrf = reg_body["data"]["csrf_token"].as_str().unwrap().to_owned();

    // Duplicate email rejected with 409 EMAIL_ALREADY_EXISTS.
    let (dup_status, _, dup_body) = send_json(
        &harness.router,
        Method::POST,
        "/api/v1/auth/register",
        None,
        None,
        Some("198.51.100.1"),
        Some(json!({
            "email": "alice@example.com",
            "password": "AnotherStrongPassword#2026"
        })),
    )
    .await;
    assert_eq!(dup_status, StatusCode::CONFLICT);
    assert_eq!(dup_body["error"]["code"], "EMAIL_ALREADY_EXISTS");

    // 2. Rehydrate via /auth/me
    let (me_status, _, me_body) = send_json(
        &harness.router,
        Method::GET,
        "/api/v1/auth/me",
        Some(&full_cookie),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(me_status, StatusCode::OK);
    assert_eq!(me_body["data"]["authenticated"], true);
    assert_eq!(me_body["data"]["user"]["email"], "alice@example.com");
    assert_eq!(me_body["data"]["csrf_token"], full_csrf);

    // 3. Create -> Read -> Update -> Delete note directly after register
    let (create_status, _, created) = send_json(
        &harness.router,
        Method::POST,
        "/api/v1/notes",
        Some(&full_cookie),
        Some(&full_csrf),
        None,
        Some(json!({
            "title": "Llave banco",
            "content": "PIN 9481 y coordenadas de respaldo",
            "category": "finanzas"
        })),
    )
    .await;
    assert_eq!(create_status, StatusCode::CREATED);
    let note_id = created["data"]["id"].as_str().unwrap().to_owned();
    assert_eq!(created["data"]["title"], "Llave banco");
    assert_eq!(created["data"]["key_version"], 1);

    let (patch_status, _, patched) = send_json(
        &harness.router,
        Method::PATCH,
        &format!("/api/v1/notes/{note_id}"),
        Some(&full_cookie),
        Some(&full_csrf),
        None,
        Some(json!({ "title": "Llave banco actualizada", "category": "documentos" })),
    )
    .await;
    assert_eq!(patch_status, StatusCode::OK);
    assert_eq!(patched["data"]["title"], "Llave banco actualizada");
    assert_eq!(
        patched["data"]["content"],
        "PIN 9481 y coordenadas de respaldo"
    );
    assert_eq!(patched["data"]["category"], "documentos");

    let (del_status, _, del_body) = send_json(
        &harness.router,
        Method::DELETE,
        &format!("/api/v1/notes/{note_id}"),
        Some(&full_cookie),
        Some(&full_csrf),
        None,
        None,
    )
    .await;
    assert_eq!(del_status, StatusCode::OK);
    assert_eq!(del_body["data"]["deleted"], true);

    // 4. Logout revokes session and clears cookie
    let (logout_status, logout_headers, logout_body) = send_json(
        &harness.router,
        Method::POST,
        "/api/v1/auth/logout",
        Some(&full_cookie),
        Some(&full_csrf),
        None,
        None,
    )
    .await;
    assert_eq!(logout_status, StatusCode::OK);
    assert_eq!(logout_body["data"]["logged_out"], true);
    let clear_cookie = logout_headers
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(clear_cookie.contains("Max-Age=0"));

    let (after_logout, _, _) = send_json(
        &harness.router,
        Method::GET,
        "/api/v1/auth/me",
        Some(&full_cookie),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(after_logout, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn ca02_auth_login_unlocks_vault_directly_and_totp_routes_return_404() {
    let harness = TestHarness::new();
    let _user = register_user(&harness.router, "bob@example.com", "BobStrongPass#2026").await;

    // Unauthenticated access to /notes returns 401 UNAUTHORIZED
    let (unauth_status, _, unauth_body) = send_json(
        &harness.router,
        Method::GET,
        "/api/v1/notes",
        None,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(unauth_status, StatusCode::UNAUTHORIZED);
    assert_eq!(unauth_body["error"]["code"], "UNAUTHORIZED");

    // Wrong password returns uniform 401 INVALID_CREDENTIALS
    let (bad_pass_status, _, bad_pass_body) = send_json(
        &harness.router,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some("198.51.100.2"),
        Some(json!({ "email": "bob@example.com", "password": "WrongPassword#2026" })),
    )
    .await;
    assert_eq!(bad_pass_status, StatusCode::UNAUTHORIZED);
    assert_eq!(bad_pass_body["error"]["code"], "INVALID_CREDENTIALS");

    // Nonexistent email returns uniform 401 INVALID_CREDENTIALS (anti-enumeration)
    let (missing_status, _, missing_body) = send_json(
        &harness.router,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some("198.51.100.2"),
        Some(json!({ "email": "nobody@example.com", "password": "BobStrongPass#2026" })),
    )
    .await;
    assert_eq!(missing_status, StatusCode::UNAUTHORIZED);
    assert_eq!(missing_body["error"]["code"], "INVALID_CREDENTIALS");

    // Standard login opens a full session and immediately unlocks /notes
    let (login_status, login_headers, login_body) = send_json(
        &harness.router,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some("198.51.100.2"),
        Some(json!({ "email": "bob@example.com", "password": "BobStrongPass#2026" })),
    )
    .await;
    assert_eq!(login_status, StatusCode::OK);
    assert_eq!(login_body["success"], true);
    assert_eq!(login_body["data"]["user"]["email"], "bob@example.com");
    assert!(login_body["data"]["csrf_token"].as_str().is_some());
    assert!(login_body["data"].get("mfa_required").is_none());

    let full_cookie = extract_cookie_value(&login_headers).unwrap();
    let full_csrf = login_body["data"]["csrf_token"]
        .as_str()
        .unwrap()
        .to_owned();

    let (notes_status, _, _) = send_json(
        &harness.router,
        Method::GET,
        "/api/v1/notes",
        Some(&full_cookie),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(notes_status, StatusCode::OK);

    // Removed TOTP endpoints MUST return 404 NOT_FOUND
    for removed_route in ["/api/v1/auth/totp/confirm", "/api/v1/auth/totp/verify"] {
        let (totp_status, _, totp_body) = send_json(
            &harness.router,
            Method::POST,
            removed_route,
            Some(&full_cookie),
            Some(&full_csrf),
            Some("198.51.100.2"),
            Some(json!({ "code": "123456" })),
        )
        .await;
        assert_eq!(
            totp_status,
            StatusCode::NOT_FOUND,
            "expected 404 on removed route {removed_route}"
        );
        assert_eq!(totp_body["success"], false);
        assert_eq!(totp_body["error"]["code"], "NOT_FOUND");
    }
}

#[tokio::test]
async fn ca03_auth_and_notes_validation_rejects_unknown_fields_and_invalid_inputs() {
    let harness = TestHarness::new();

    // Unknown field on register -> 400 VALIDATION_ERROR
    let (s1, _, b1) = send_json(
        &harness.router,
        Method::POST,
        "/api/v1/auth/register",
        None,
        None,
        None,
        Some(json!({
            "email": "val@example.com",
            "password": "ValidPassword#2026",
            "is_admin": true
        })),
    )
    .await;
    assert_eq!(s1, StatusCode::BAD_REQUEST);
    assert_eq!(b1["success"], false);
    assert_eq!(b1["error"]["code"], "VALIDATION_ERROR");

    // Weak password (< 12 chars) -> 400 VALIDATION_ERROR
    let (s2, _, b2) = send_json(
        &harness.router,
        Method::POST,
        "/api/v1/auth/register",
        None,
        None,
        None,
        Some(json!({
            "email": "val@example.com",
            "password": "short"
        })),
    )
    .await;
    assert_eq!(s2, StatusCode::BAD_REQUEST);
    assert_eq!(b2["error"]["code"], "VALIDATION_ERROR");

    let user = register_user(&harness.router, "val@example.com", "ValidPassword#2026").await;

    // Invalid category -> 400 VALIDATION_ERROR
    let (s3, _, b3) = send_json(
        &harness.router,
        Method::POST,
        "/api/v1/notes",
        Some(&user.cookie),
        Some(&user.csrf_token),
        None,
        Some(json!({
            "title": "Titulo",
            "content": "Contenido",
            "category": "prohibida"
        })),
    )
    .await;
    assert_eq!(s3, StatusCode::BAD_REQUEST);
    assert_eq!(b3["error"]["code"], "VALIDATION_ERROR");

    // Empty title / whitespace content -> 400 VALIDATION_ERROR
    let (s4, _, b4) = send_json(
        &harness.router,
        Method::POST,
        "/api/v1/notes",
        Some(&user.cookie),
        Some(&user.csrf_token),
        None,
        Some(json!({
            "title": "   ",
            "content": "Contenido",
            "category": "general"
        })),
    )
    .await;
    assert_eq!(s4, StatusCode::BAD_REQUEST);
    assert_eq!(b4["error"]["code"], "VALIDATION_ERROR");

    // Extra field on create note -> 400 VALIDATION_ERROR
    let (s5, _, b5) = send_json(
        &harness.router,
        Method::POST,
        "/api/v1/notes",
        Some(&user.cookie),
        Some(&user.csrf_token),
        None,
        Some(json!({
            "title": "Ok",
            "content": "Ok",
            "category": "general",
            "user_id": Uuid::new_v4().to_string()
        })),
    )
    .await;
    assert_eq!(s5, StatusCode::BAD_REQUEST);
    assert_eq!(b5["error"]["code"], "VALIDATION_ERROR");

    // Invalid UUID path and invalid pagination query -> 400 VALIDATION_ERROR
    let (s6, _, b6) = send_json(
        &harness.router,
        Method::GET,
        "/api/v1/notes/not-a-uuid",
        Some(&user.cookie),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(s6, StatusCode::BAD_REQUEST);
    assert_eq!(b6["error"]["code"], "VALIDATION_ERROR");

    let (s7, _, b7) = send_json(
        &harness.router,
        Method::GET,
        "/api/v1/notes?page=0",
        Some(&user.cookie),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(s7, StatusCode::BAD_REQUEST);
    assert_eq!(b7["error"]["code"], "VALIDATION_ERROR");
}

#[tokio::test]
async fn ca04_empty_notes_list_and_paginated_category_filtering() {
    let harness = TestHarness::new();
    let user = register_user(&harness.router, "empty@example.com", "EmptyListPass#2026").await;

    let (status, _, body) = send_json(
        &harness.router,
        Method::GET,
        "/api/v1/notes",
        Some(&user.cookie),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["success"], true);
    assert_eq!(body["data"].as_array().unwrap().len(), 0);
    assert_eq!(body["meta"]["total"], 0);
    assert_eq!(body["meta"]["page"], 1);
    assert_eq!(body["meta"]["limit"], 20);
    assert_eq!(body["meta"]["totalPages"], 0);

    // Create 3 notes across categories
    for (title, category) in [
        ("Finanzas 1", "finanzas"),
        ("Personal 1", "personal"),
        ("Finanzas 2", "finanzas"),
    ] {
        let (st, _, _) = send_json(
            &harness.router,
            Method::POST,
            "/api/v1/notes",
            Some(&user.cookie),
            Some(&user.csrf_token),
            None,
            Some(json!({ "title": title, "content": "Secreto", "category": category })),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);
    }

    let (f_status, _, f_body) = send_json(
        &harness.router,
        Method::GET,
        "/api/v1/notes?category=finanzas&page=1&limit=1",
        Some(&user.cookie),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(f_status, StatusCode::OK);
    assert_eq!(f_body["data"].as_array().unwrap().len(), 1);
    assert_eq!(f_body["meta"]["total"], 2);
    assert_eq!(f_body["meta"]["totalPages"], 2);
    assert_eq!(f_body["data"][0]["category"], "finanzas");
}

#[tokio::test]
async fn ca05_bola_isolation_between_users_and_csrf_protection() {
    let harness = TestHarness::new();
    let user_a = register_user(&harness.router, "usera@example.com", "UserAStrongPass#2026").await;
    let user_b = register_user(&harness.router, "userb@example.com", "UserBStrongPass#2026").await;

    let (status, _, created) = send_json(
        &harness.router,
        Method::POST,
        "/api/v1/notes",
        Some(&user_a.cookie),
        Some(&user_a.csrf_token),
        None,
        Some(json!({
            "title": "Solo de A",
            "content": "Secreto privado de A",
            "category": "credenciales"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let note_id = created["data"]["id"].as_str().unwrap();

    // User B cannot GET, PATCH, or DELETE User A's note -> 404 NOT_FOUND
    let (get_b, _, get_b_body) = send_json(
        &harness.router,
        Method::GET,
        &format!("/api/v1/notes/{note_id}"),
        Some(&user_b.cookie),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(get_b, StatusCode::NOT_FOUND);
    assert_eq!(get_b_body["error"]["code"], "NOT_FOUND");

    let (patch_b, _, _) = send_json(
        &harness.router,
        Method::PATCH,
        &format!("/api/v1/notes/{note_id}"),
        Some(&user_b.cookie),
        Some(&user_b.csrf_token),
        None,
        Some(json!({ "title": "Hackeado" })),
    )
    .await;
    assert_eq!(patch_b, StatusCode::NOT_FOUND);

    let (del_b, _, _) = send_json(
        &harness.router,
        Method::DELETE,
        &format!("/api/v1/notes/{note_id}"),
        Some(&user_b.cookie),
        Some(&user_b.csrf_token),
        None,
        None,
    )
    .await;
    assert_eq!(del_b, StatusCode::NOT_FOUND);

    // Missing or invalid CSRF token on mutations -> 403 CSRF_INVALID
    let (no_csrf, _, no_csrf_body) = send_json(
        &harness.router,
        Method::POST,
        "/api/v1/notes",
        Some(&user_a.cookie),
        None,
        None,
        Some(json!({ "title": "X", "content": "Y", "category": "general" })),
    )
    .await;
    assert_eq!(no_csrf, StatusCode::FORBIDDEN);
    assert_eq!(no_csrf_body["error"]["code"], "CSRF_INVALID");

    let (bad_csrf, _, bad_csrf_body) = send_json(
        &harness.router,
        Method::DELETE,
        &format!("/api/v1/notes/{note_id}"),
        Some(&user_a.cookie),
        Some("wrong-csrf-token"),
        None,
        None,
    )
    .await;
    assert_eq!(bad_csrf, StatusCode::FORBIDDEN);
    assert_eq!(bad_csrf_body["error"]["code"], "CSRF_INVALID");

    // User A can still read their untouched note
    let (get_a, _, body_a) = send_json(
        &harness.router,
        Method::GET,
        &format!("/api/v1/notes/{note_id}"),
        Some(&user_a.cookie),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(get_a, StatusCode::OK);
    assert_eq!(body_a["data"]["title"], "Solo de A");
}

#[tokio::test]
async fn ca06_encryption_at_rest_tampering_alert_and_key_rotation_v1_to_v2() {
    let harness = TestHarness::new();
    let user = register_user(&harness.router, "crypto@example.com", "CryptoPass#2026!").await;

    let secret_title = "Clave Maestra de Boveda";
    let secret_content = "frase-semilla-ultra-confidencial-2026";
    let (status, _, created) = send_json(
        &harness.router,
        Method::POST,
        "/api/v1/notes",
        Some(&user.cookie),
        Some(&user.csrf_token),
        Some("203.0.113.77"),
        Some(json!({
            "title": secret_title,
            "content": secret_content,
            "category": "credenciales"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let note_id = Uuid::parse_str(created["data"]["id"].as_str().unwrap()).unwrap();

    // Direct inspection in store: zero plaintext in ciphertext columns
    let raw_note = harness.store.inspect_note_raw(note_id).await.unwrap();
    assert_eq!(raw_note.key_version, 1);
    assert!(
        !raw_note
            .title_ciphertext
            .windows(secret_title.len())
            .any(|w| w == secret_title.as_bytes())
    );
    assert!(
        !raw_note
            .content_ciphertext
            .windows(secret_content.len())
            .any(|w| w == secret_content.as_bytes())
    );

    let raw_user = harness.store.inspect_user_raw(user.user_id).await.unwrap();
    assert_eq!(raw_user.totp_key_version, 1);
    assert!(!raw_user.totp_enabled);
    assert_eq!(raw_user.totp_secret_ciphertext.len(), 36);
    assert_eq!(raw_user.totp_secret_nonce.len(), 12);

    // Flip 1 byte of content_ciphertext -> 500 generic error + crypto_integrity_failure alert
    assert!(harness.store.tamper_note_content_byte(note_id).await);
    let (tamper_status, _, tamper_body) = send_json(
        &harness.router,
        Method::GET,
        &format!("/api/v1/notes/{note_id}"),
        Some(&user.cookie),
        None,
        Some("203.0.113.77"),
        None,
    )
    .await;
    assert_eq!(tamper_status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(tamper_body["error"]["code"], "INTERNAL_ERROR");
    assert_eq!(
        tamper_body["error"]["message"],
        "Error interno del servidor"
    );

    // Allow background alert worker to receive the message
    tokio::time::sleep(Duration::from_millis(50)).await;
    let alerts = harness.alerts_sink.captured().await;
    assert!(
        alerts
            .iter()
            .any(|a| a.event == "crypto_integrity_failure" && a.severity == "critical"),
        "expected crypto_integrity_failure alert, got: {alerts:?}"
    );
    for alert in &alerts {
        assert_eq!(alert.ip_hash.len(), 16);
        assert!(!alert.ip_hash.contains("203.0.113.77"));
    }

    // Restore flipped byte so we can verify v1 -> v2 key rotation
    assert!(harness.store.tamper_note_content_byte(note_id).await);

    // Upgrade KeyRing to v2 active while retaining v1
    let ring_v1_v2 = make_key_ring(2, &[(1, 0x11), (2, 0x22)]);
    let repos = VaultRepositories::from_in_memory(Arc::clone(&harness.store));
    let config_v2 = make_config(AppEnv::Development, true, ring_v1_v2.clone());
    let alerts_v2 = AlertService::spawn(Arc::clone(&harness.alerts_sink) as _, test_pepper());
    let router_v2 = build_router(AppState::new(&config_v2, repos.clone(), alerts_v2));

    // Old v1 note still decrypts cleanly
    let (read_v1, _, read_v1_body) = send_json(
        &router_v2,
        Method::GET,
        &format!("/api/v1/notes/{note_id}"),
        Some(&user.cookie),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(read_v1, StatusCode::OK);
    assert_eq!(read_v1_body["data"]["content"], secret_content);

    // New note is encrypted with key_version = 2
    let (v2_status, _, created_v2) = send_json(
        &router_v2,
        Method::POST,
        "/api/v1/notes",
        Some(&user.cookie),
        Some(&user.csrf_token),
        None,
        Some(json!({
            "title": "Nota V2",
            "content": "Cifrada con llave 2",
            "category": "general"
        })),
    )
    .await;
    assert_eq!(v2_status, StatusCode::CREATED);
    assert_eq!(created_v2["data"]["key_version"], 2);

    // Run idempotent batch rotation (v1 -> v2)
    let report1 = rotate_all_keys(&repos, &ring_v1_v2, 10).await.unwrap();
    assert_eq!(report1.active_version, 2);
    assert_eq!(report1.notes_rotated, 1);
    assert_eq!(report1.users_rotated, 1);

    // Re-running rotation is a no-op (idempotent)
    let report2 = rotate_all_keys(&repos, &ring_v1_v2, 10).await.unwrap();
    assert_eq!(report2.notes_rotated, 0);
    assert_eq!(report2.users_rotated, 0);

    // Verify stored key versions updated to 2
    assert_eq!(
        harness
            .store
            .inspect_note_raw(note_id)
            .await
            .unwrap()
            .key_version,
        2
    );
    assert_eq!(
        harness
            .store
            .inspect_user_raw(user.user_id)
            .await
            .unwrap()
            .totp_key_version,
        2
    );

    // Retire v1 completely: router with ONLY v2 can still read rotated note and verify TOTP
    let ring_only_v2 = make_key_ring(2, &[(2, 0x22)]);
    let config_only_v2 = make_config(AppEnv::Development, true, ring_only_v2);
    let alerts_only_v2 = AlertService::spawn(Arc::clone(&harness.alerts_sink) as _, test_pepper());
    let router_only_v2 = build_router(AppState::new(&config_only_v2, repos, alerts_only_v2));

    let (read_after_retire, _, read_after_body) = send_json(
        &router_only_v2,
        Method::GET,
        &format!("/api/v1/notes/{note_id}"),
        Some(&user.cookie),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(read_after_retire, StatusCode::OK);
    assert_eq!(read_after_body["data"]["title"], secret_title);
    assert_eq!(read_after_body["data"]["content"], secret_content);
    assert_eq!(read_after_body["data"]["key_version"], 2);
}

#[tokio::test]
async fn ca07_auth_bruteforce_locks_account_and_sends_sanitized_webhook() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = socket.read(&mut buf).await.unwrap();
        let raw = String::from_utf8_lossy(&buf[..n]).into_owned();
        let _ = socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await;
        let _ = tx.send(raw);
    });

    let store = Arc::new(InMemoryStore::new());
    let repos = VaultRepositories::from_in_memory(store);
    let webhook_url = SecretString::from(format!("http://{addr}/alerts"));
    let alerts =
        AlertService::from_webhook_config(Some(webhook_url), WebhookFormat::Generic, test_pepper());
    let config = make_config(AppEnv::Development, true, make_key_ring(1, &[(1, 0x11)]));
    let router = build_router(AppState::with_rate_limits(
        &config,
        repos,
        alerts,
        RateLimitConfig {
            auth_max_requests: 100,
            api_max_requests: 100,
            window: Duration::from_secs(60),
        },
    ));

    let email = "victim@example.com";
    let real_password = "RealPassword#2026!";
    let wrong_password = "WrongPassword#2026!";
    let attacker_ip = "203.0.113.55";

    let _ = register_user(&router, email, real_password).await;

    // Attempts 1..=4 return 401 INVALID_CREDENTIALS
    for _ in 0..4 {
        let (st, _, body) = send_json(
            &router,
            Method::POST,
            "/api/v1/auth/login",
            None,
            None,
            Some(attacker_ip),
            Some(json!({ "email": email, "password": wrong_password })),
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "INVALID_CREDENTIALS");
    }

    // 5th attempt triggers 429 ACCOUNT_LOCKED and dispatches sanitized webhook
    let (st5, _, b5) = send_json(
        &router,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some(attacker_ip),
        Some(json!({ "email": email, "password": wrong_password })),
    )
    .await;
    assert_eq!(st5, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(b5["error"]["code"], "ACCOUNT_LOCKED");

    // 6th attempt even with correct password remains locked
    let (st6, _, b6) = send_json(
        &router,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some(attacker_ip),
        Some(json!({ "email": email, "password": real_password })),
    )
    .await;
    assert_eq!(st6, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(b6["error"]["code"], "ACCOUNT_LOCKED");

    // Verify real HTTP webhook payload contains zero PII or secrets
    let raw_webhook = tokio::time::timeout(Duration::from_secs(3), rx)
        .await
        .unwrap()
        .unwrap();
    assert!(raw_webhook.contains("auth_bruteforce"));
    assert!(raw_webhook.contains("ACCOUNT_LOCKED"));
    assert!(!raw_webhook.contains(email));
    assert!(!raw_webhook.contains(real_password));
    assert!(!raw_webhook.contains(wrong_password));
    assert!(!raw_webhook.contains(attacker_ip));
}

#[tokio::test]
async fn ca08_stalling_webhook_never_blocks_or_breaks_http_responses() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Accept connection and intentionally hang for 10s
    tokio::spawn(async move {
        if let Ok((_socket, _)) = listener.accept().await {
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    });

    let store = Arc::new(InMemoryStore::new());
    let repos = VaultRepositories::from_in_memory(store);
    let sink = Arc::new(
        HttpWebhookSink::new(
            SecretString::from(format!("http://{addr}/hang")),
            WebhookFormat::Slack,
        )
        .unwrap(),
    );
    let alerts = AlertService::spawn(sink, test_pepper());
    let config = make_config(AppEnv::Development, true, make_key_ring(1, &[(1, 0x11)]));
    let router = build_router(AppState::new(&config, repos, alerts));

    let _ = register_user(&router, "resilient@example.com", "ResilientPass#2026").await;

    for _ in 0..4 {
        let (st, _, _) = send_json(
            &router,
            Method::POST,
            "/api/v1/auth/login",
            None,
            None,
            Some("198.51.100.88"),
            Some(json!({ "email": "resilient@example.com", "password": "BadPassword#2026" })),
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
    }

    let started = Instant::now();
    let (st5, _, b5) = send_json(
        &router,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some("198.51.100.88"),
        Some(json!({ "email": "resilient@example.com", "password": "BadPassword#2026" })),
    )
    .await;
    assert_eq!(st5, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(b5["error"]["code"], "ACCOUNT_LOCKED");
    // Response returned well before the 5-second webhook timeout / 10-second TCP stall.
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "HTTP response waited too long: {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn ca09_auth_registration_disabled_returns_403() {
    let harness = TestHarness::with_options(
        AppEnv::Development,
        false,
        make_key_ring(1, &[(1, 0x11)]),
        RateLimitConfig::default(),
    );

    let (status, _, body) = send_json(
        &harness.router,
        Method::POST,
        "/api/v1/auth/register",
        None,
        None,
        None,
        Some(json!({
            "email": "closed@example.com",
            "password": "ValidPassword#2026"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "REGISTRATION_DISABLED");
}

#[tokio::test]
async fn healthz_and_security_headers_including_hsts_in_production() {
    // Development mode: no HSTS
    let dev = TestHarness::new();
    let (status, headers, body) =
        send_json(&dev.router, Method::GET, "/healthz", None, None, None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
    assert_eq!(
        headers.get(header::X_CONTENT_TYPE_OPTIONS),
        Some(&HeaderValue::from_static("nosniff"))
    );
    assert_eq!(
        headers.get(header::X_FRAME_OPTIONS),
        Some(&HeaderValue::from_static("DENY"))
    );
    assert_eq!(
        headers.get(header::REFERRER_POLICY),
        Some(&HeaderValue::from_static("no-referrer"))
    );
    assert!(headers.get("permissions-policy").is_some());
    assert!(
        headers
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
    assert!(headers.get("x-request-id").is_some());
    assert!(headers.get(header::STRICT_TRANSPORT_SECURITY).is_none());

    // Production mode: HSTS + Secure cookie + Cache-Control: no-store on /api/v1
    let prod = TestHarness::with_options(
        AppEnv::Production,
        true,
        make_key_ring(1, &[(1, 0x11)]),
        RateLimitConfig::default(),
    );

    let (reg_status, reg_headers, _) = send_json(
        &prod.router,
        Method::POST,
        "/api/v1/auth/register",
        None,
        None,
        None,
        Some(json!({
            "email": "prod@example.com",
            "password": "ProdStrongPassword#2026"
        })),
    )
    .await;
    assert_eq!(reg_status, StatusCode::CREATED);
    assert_eq!(
        reg_headers.get(header::STRICT_TRANSPORT_SECURITY),
        Some(&HeaderValue::from_static(
            "max-age=31536000; includeSubDomains"
        ))
    );
    assert_eq!(
        reg_headers.get(header::CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );
    assert!(
        reg_headers
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("; Secure")
    );
}

#[tokio::test]
async fn ca07_ip_rate_limiting_returns_429() {
    // Per-IP rate limiter returns 429 RATE_LIMITED
    let strict_rl = TestHarness::with_options(
        AppEnv::Development,
        true,
        make_key_ring(1, &[(1, 0x11)]),
        RateLimitConfig {
            auth_max_requests: 2,
            api_max_requests: 10,
            window: Duration::from_secs(60),
        },
    );

    for _ in 0..2 {
        let (st, _, _) = send_json(
            &strict_rl.router,
            Method::GET,
            "/api/v1/auth/me",
            None,
            None,
            Some("198.51.100.99"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
    }

    let (rl_st, _, rl_body) = send_json(
        &strict_rl.router,
        Method::GET,
        "/api/v1/auth/me",
        None,
        None,
        Some("198.51.100.99"),
        None,
    )
    .await;
    assert_eq!(rl_st, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(rl_body["error"]["code"], "RATE_LIMITED");
}

#[tokio::test]
async fn ca07_internal_5xx_returns_generic_message_and_emits_http_5xx_alert() {
    use security_vault_backend::{
        domain::{
            error::AppError,
            models::{EncryptedNoteRecord, NoteCategory},
        },
        repositories::{NoteRepository, RepoFuture},
    };

    struct FailingNoteRepo;

    impl NoteRepository for FailingNoteRepo {
        fn create_note(&self, _note: EncryptedNoteRecord) -> RepoFuture<'_, EncryptedNoteRecord> {
            Box::pin(async {
                Err(AppError::Internal(
                    "simulated db outage password=TOPSECRET".to_owned(),
                ))
            })
        }

        fn list_notes(
            &self,
            _user_id: Uuid,
            _category: Option<NoteCategory>,
            _page: u32,
            _limit: u32,
        ) -> RepoFuture<'_, (Vec<EncryptedNoteRecord>, u64)> {
            Box::pin(async {
                Err(AppError::Internal(
                    "simulated db outage password=TOPSECRET".to_owned(),
                ))
            })
        }

        fn find_note_by_id(
            &self,
            _note_id: Uuid,
            _user_id: Uuid,
        ) -> RepoFuture<'_, Option<EncryptedNoteRecord>> {
            Box::pin(async { Err(AppError::Internal("simulated db outage".to_owned())) })
        }

        fn update_note(
            &self,
            _note: EncryptedNoteRecord,
        ) -> RepoFuture<'_, Option<EncryptedNoteRecord>> {
            Box::pin(async { Err(AppError::Internal("simulated db outage".to_owned())) })
        }

        fn delete_note(&self, _note_id: Uuid, _user_id: Uuid) -> RepoFuture<'_, bool> {
            Box::pin(async { Err(AppError::Internal("simulated db outage".to_owned())) })
        }

        fn list_notes_with_key_version_ne(
            &self,
            _active_version: i16,
            _limit: i64,
        ) -> RepoFuture<'_, Vec<EncryptedNoteRecord>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn update_note_encryption(
            &self,
            _note_id: Uuid,
            _user_id: Uuid,
            _title_ciphertext: Vec<u8>,
            _title_nonce: Vec<u8>,
            _content_ciphertext: Vec<u8>,
            _content_nonce: Vec<u8>,
            _key_version: i16,
        ) -> RepoFuture<'_, bool> {
            Box::pin(async { Ok(false) })
        }
    }

    let store = Arc::new(InMemoryStore::new());
    let mut repos = VaultRepositories::from_in_memory(Arc::clone(&store));
    repos.notes = Arc::new(FailingNoteRepo);

    let sink = Arc::new(RecordingAlertSink::new());
    let alerts = AlertService::spawn(Arc::clone(&sink) as _, test_pepper());
    let config = make_config(AppEnv::Development, true, make_key_ring(1, &[(1, 0x11)]));
    let router = build_router(AppState::new(&config, repos, alerts));

    let user = register_user(&router, "err500@example.com", "Err500Pass#2026!").await;

    let (status, _, body) = send_json(
        &router,
        Method::GET,
        "/api/v1/notes",
        Some(&user.cookie),
        None,
        Some("203.0.113.199"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["error"]["code"], "INTERNAL_ERROR");
    assert_eq!(body["error"]["message"], "Error interno del servidor");
    assert!(!body.to_string().contains("TOPSECRET"));

    tokio::time::sleep(Duration::from_millis(50)).await;
    let captured = sink.captured().await;
    assert!(
        captured.iter().any(|a| a.event == "http_5xx"
            && a.severity == "critical"
            && a.code == "INTERNAL_ERROR"),
        "expected http_5xx alert, got: {captured:?}"
    );
}

struct TempDirGuard(std::path::PathBuf);

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn send_raw(router: &Router, uri: &str) -> (StatusCode, HeaderMap, String) {
    let request = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    (status, headers, text)
}

#[tokio::test]
async fn spa_static_files_fallback_security_headers_and_api_json_404() {
    let temp_dir = TempDirGuard(
        std::env::temp_dir().join(format!("securityvault-spa-test-{}", Uuid::new_v4())),
    );
    let assets_dir = temp_dir.0.join("assets");
    std::fs::create_dir_all(&assets_dir).unwrap();

    let index_html =
        "<!doctype html><html><body><div id=\"root\">SecurityVault SPA</div></body></html>";
    let app_js = "console.log('securityvault-bundle-v1');";
    std::fs::write(temp_dir.0.join("index.html"), index_html).unwrap();
    std::fs::write(assets_dir.join("app.js"), app_js).unwrap();

    let store = Arc::new(InMemoryStore::new());
    let repos = VaultRepositories::from_in_memory(store);
    let sink = Arc::new(RecordingAlertSink::new());
    let alerts = AlertService::spawn(sink, test_pepper());

    let mut config = make_config(AppEnv::Production, true, make_key_ring(1, &[(1, 0x11)]));
    config.static_dir = Some(temp_dir.0.clone());
    let router = build_router(AppState::new(&config, repos, alerts));

    // 1. GET / and GET /vault (SPA fallback) -> 200 with index.html and full security headers
    for path in ["/", "/vault", "/login"] {
        let (status, headers, body) = send_raw(&router, path).await;
        assert_eq!(status, StatusCode::OK, "expected 200 for {path}");
        assert_eq!(body, index_html);
        assert_eq!(
            headers.get(header::X_CONTENT_TYPE_OPTIONS),
            Some(&HeaderValue::from_static("nosniff"))
        );
        assert_eq!(
            headers.get(header::X_FRAME_OPTIONS),
            Some(&HeaderValue::from_static("DENY"))
        );
        assert_eq!(
            headers.get(header::REFERRER_POLICY),
            Some(&HeaderValue::from_static("no-referrer"))
        );
        assert!(headers.get(header::CONTENT_SECURITY_POLICY).is_some());
        assert!(headers.get(header::STRICT_TRANSPORT_SECURITY).is_some());
        assert!(headers.get("permissions-policy").is_some());
        assert_ne!(
            headers.get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
    }

    // 2. GET /assets/app.js -> 200 with JS content, security headers, and cacheable header
    let (asset_status, asset_headers, asset_body) = send_raw(&router, "/assets/app.js").await;
    assert_eq!(asset_status, StatusCode::OK);
    assert_eq!(asset_body, app_js);
    assert_eq!(
        asset_headers.get(header::X_CONTENT_TYPE_OPTIONS),
        Some(&HeaderValue::from_static("nosniff"))
    );
    assert_eq!(
        asset_headers.get(header::CACHE_CONTROL),
        Some(&HeaderValue::from_static(
            "public, max-age=31536000, immutable"
        ))
    );

    // 3. Unknown /api/v1/* and /api/* routes MUST return 404 JSON NOT_FOUND (never index.html)
    let (api_v1_status, api_v1_headers, api_v1_body) = send_json(
        &router,
        Method::GET,
        "/api/v1/ruta-inexistente",
        None,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(api_v1_status, StatusCode::NOT_FOUND);
    assert_eq!(api_v1_body["success"], false);
    assert_eq!(api_v1_body["error"]["code"], "NOT_FOUND");
    assert_eq!(
        api_v1_headers.get(header::CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );

    let (api_other_status, _, api_other_body) = send_json(
        &router,
        Method::GET,
        "/api/ruta-desconocida",
        None,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(api_other_status, StatusCode::NOT_FOUND);
    assert_eq!(api_other_body["success"], false);
    assert_eq!(api_other_body["error"]["code"], "NOT_FOUND");
}
