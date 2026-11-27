//! Asynchronous external security alerting over a bounded channel (`mpsc::channel(64)`).
//!
//! Delivery is strictly fire-and-forget (`try_send`) with a 5-second network timeout so that
//! webhook slowness or outages can never block or break user-facing HTTP responses (CA-08).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::{Mutex, mpsc};

use crate::config::WebhookFormat;
use crate::crypto::totp::keyed_sha256_hex;

/// Bounded capacity of the alert delivery queue (backpressure against OOM/DoS).
pub const ALERT_CHANNEL_CAPACITY: usize = 64;

/// Maximum network/sink time allowed per webhook dispatch.
pub const ALERT_DISPATCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum character length allowed for sanitized `request_id` and `code` fields.
const MAX_FIELD_LEN: usize = 64;

/// Supported security alert event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertEventKind {
    /// Repeated authentication/TOTP failures crossing the brute-force lockout threshold.
    AuthBruteforce,
    /// Unhandled 5xx HTTP error returned by the server.
    Http5xx,
    /// AES-256-GCM authentication tag or AAD verification failure during decryption.
    CryptoIntegrityFailure,
}

impl AlertEventKind {
    /// Returns the canonical `snake_case` event name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthBruteforce => "auth_bruteforce",
            Self::Http5xx => "http_5xx",
            Self::CryptoIntegrityFailure => "crypto_integrity_failure",
        }
    }

    /// Returns the alert severity level.
    #[must_use]
    pub const fn severity(self) -> &'static str {
        match self {
            Self::AuthBruteforce => "high",
            Self::Http5xx | Self::CryptoIntegrityFailure => "critical",
        }
    }
}

/// Strictly sanitized alert payload emitted to external webhooks (zero PII, zero secrets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertPayload {
    pub event: String,
    pub severity: String,
    pub timestamp: String,
    pub request_id: String,
    pub ip_hash: String,
    pub code: String,
}

impl AlertPayload {
    /// Constructs a strictly sanitized payload using a keyed SHA-256 hash of `client_ip`
    /// truncated to 16 lowercase hex characters.
    #[must_use]
    pub fn build(
        kind: AlertEventKind,
        request_id: &str,
        client_ip: &str,
        code: &str,
        pepper: &SecretString,
    ) -> Self {
        let timestamp = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());

        let ip_hash = hash_ip_truncated(pepper, client_ip);

        Self {
            event: kind.as_str().to_owned(),
            severity: kind.severity().to_owned(),
            timestamp,
            request_id: sanitize_token(request_id),
            ip_hash,
            code: sanitize_token(code),
        }
    }
}

/// Computes a keyed SHA-256 hash of a client IP truncated to 16 hex characters (64 bits).
#[must_use]
pub fn hash_ip_truncated(pepper: &SecretString, client_ip: &str) -> String {
    match keyed_sha256_hex(pepper, "alert-ip", client_ip.trim()) {
        Ok(full_hex) => full_hex.chars().take(16).collect(),
        Err(_) => "0000000000000000".to_owned(),
    }
}

/// Sanitizes short identifier/code fields by removing control characters and bounding length.
fn sanitize_token(raw: &str) -> String {
    let cleaned: String = raw
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .take(MAX_FIELD_LEN)
        .collect();
    if cleaned.is_empty() {
        "unknown".to_owned()
    } else {
        cleaned
    }
}

/// Formats an [`AlertPayload`] into the JSON body expected by the configured webhook target.
#[must_use]
pub fn format_webhook_body(payload: &AlertPayload, format: WebhookFormat) -> serde_json::Value {
    match format {
        WebhookFormat::Generic => json!({
            "event": payload.event,
            "severity": payload.severity,
            "timestamp": payload.timestamp,
            "request_id": payload.request_id,
            "ip_hash": payload.ip_hash,
            "code": payload.code,
        }),
        WebhookFormat::Discord => {
            let color: u32 = if payload.severity == "critical" {
                0x00DC_2626
            } else {
                0x00D9_7706
            };
            json!({
                "content": format!(
                    "[SecurityVault][{}] {} ({})",
                    payload.severity.to_ascii_uppercase(),
                    payload.event,
                    payload.code
                ),
                "embeds": [
                    {
                        "title": format!("SecurityVault Alert: {}", payload.event),
                        "color": color,
                        "fields": [
                            { "name": "event", "value": payload.event, "inline": true },
                            { "name": "severity", "value": payload.severity, "inline": true },
                            { "name": "code", "value": payload.code, "inline": true },
                            { "name": "request_id", "value": payload.request_id, "inline": false },
                            { "name": "ip_hash", "value": payload.ip_hash, "inline": true },
                            { "name": "timestamp", "value": payload.timestamp, "inline": true }
                        ]
                    }
                ]
            })
        }
        WebhookFormat::Slack => json!({
            "text": format!(
                "[SecurityVault] severity={} event={} code={} request_id={} ip_hash={} timestamp={}",
                payload.severity,
                payload.event,
                payload.code,
                payload.request_id,
                payload.ip_hash,
                payload.timestamp
            )
        }),
    }
}

/// Boxed future returned by [`AlertSink::send`].
pub type SinkFuture<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

/// Pluggable sink abstraction for alert delivery (HTTP webhook, no-op, or test spy).
pub trait AlertSink: Send + Sync {
    /// Dispatches a single sanitized alert payload.
    fn send(&self, payload: AlertPayload) -> SinkFuture<'_>;
}

/// No-op sink used when `ALERT_WEBHOOK_URL` is not configured.
#[derive(Debug, Default)]
pub struct NoopAlertSink;

impl AlertSink for NoopAlertSink {
    fn send(&self, _payload: AlertPayload) -> SinkFuture<'_> {
        Box::pin(async { Ok(()) })
    }
}

/// HTTP webhook sink using `reqwest` with strict timeouts and redirects disabled.
pub struct HttpWebhookSink {
    client: reqwest::Client,
    webhook_url: SecretString,
    format: WebhookFormat,
}

impl HttpWebhookSink {
    /// Creates an HTTP webhook sink with a 5-second total timeout and no HTTP redirects.
    pub fn new(webhook_url: SecretString, format: WebhookFormat) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(ALERT_DISPATCH_TIMEOUT)
            .connect_timeout(Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| format!("failed to build webhook HTTP client: {err}"))?;

        Ok(Self {
            client,
            webhook_url,
            format,
        })
    }
}

impl AlertSink for HttpWebhookSink {
    fn send(&self, payload: AlertPayload) -> SinkFuture<'_> {
        let body = format_webhook_body(&payload, self.format);
        Box::pin(async move {
            let response = self
                .client
                .post(self.webhook_url.expose_secret())
                .json(&body)
                .send()
                .await
                .map_err(|err| format!("webhook network error: {}", err.without_url()))?;

            if response.status().is_success() {
                Ok(())
            } else {
                Err(format!(
                    "webhook returned non-success status {}",
                    response.status().as_u16()
                ))
            }
        })
    }
}

/// In-memory recording sink for deterministic unit and integration testing.
#[derive(Default)]
pub struct RecordingAlertSink {
    events: Mutex<Vec<AlertPayload>>,
}

impl RecordingAlertSink {
    /// Creates an empty recording sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a snapshot of all alerts received so far.
    pub async fn captured(&self) -> Vec<AlertPayload> {
        self.events.lock().await.clone()
    }
}

impl AlertSink for RecordingAlertSink {
    fn send(&self, payload: AlertPayload) -> SinkFuture<'_> {
        Box::pin(async move {
            self.events.lock().await.push(payload);
            Ok(())
        })
    }
}

/// Non-blocking alert dispatcher backed by a bounded `mpsc::channel(64)` worker.
#[derive(Clone)]
pub struct AlertService {
    tx: mpsc::Sender<AlertPayload>,
    pepper: SecretString,
}

impl AlertService {
    /// Spawns a background worker consuming from a bounded channel (`ALERT_CHANNEL_CAPACITY`)
    /// and dispatching to `sink` with a hard 5-second timeout per alert.
    #[must_use]
    pub fn spawn(sink: Arc<dyn AlertSink>, pepper: SecretString) -> Self {
        Self::spawn_with_timeout(sink, pepper, ALERT_DISPATCH_TIMEOUT)
    }

    /// Spawns a background worker with a custom per-dispatch timeout (useful in resilience tests).
    #[must_use]
    pub fn spawn_with_timeout(
        sink: Arc<dyn AlertSink>,
        pepper: SecretString,
        dispatch_timeout: Duration,
    ) -> Self {
        let (tx, mut rx) = mpsc::channel::<AlertPayload>(ALERT_CHANNEL_CAPACITY);

        tokio::spawn(async move {
            while let Some(payload) = rx.recv().await {
                let event_name = payload.event.clone();
                let req_id = payload.request_id.clone();
                match tokio::time::timeout(dispatch_timeout, sink.send(payload)).await {
                    Ok(Ok(())) => {
                        tracing::info!(
                            alert_event = %event_name,
                            request_id = %req_id,
                            "security alert dispatched"
                        );
                    }
                    Ok(Err(reason)) => {
                        tracing::warn!(
                            alert_event = %event_name,
                            request_id = %req_id,
                            reason = %reason,
                            "security alert dispatch failed"
                        );
                    }
                    Err(_) => {
                        tracing::warn!(
                            alert_event = %event_name,
                            request_id = %req_id,
                            "security alert dispatch timed out"
                        );
                    }
                }
            }
        });

        Self { tx, pepper }
    }

    /// Builds an [`AlertService`] from optional webhook config (falls back to [`NoopAlertSink`]).
    #[must_use]
    pub fn from_webhook_config(
        webhook_url: Option<SecretString>,
        format: WebhookFormat,
        pepper: SecretString,
    ) -> Self {
        let sink: Arc<dyn AlertSink> = match webhook_url {
            Some(url) => match HttpWebhookSink::new(url, format) {
                Ok(http_sink) => Arc::new(http_sink),
                Err(reason) => {
                    tracing::warn!(reason = %reason, "falling back to noop alert sink");
                    Arc::new(NoopAlertSink)
                }
            },
            None => Arc::new(NoopAlertSink),
        };
        Self::spawn(sink, pepper)
    }

    /// Enqueues a sanitized security alert without ever blocking the caller.
    ///
    /// Returns `true` if queued, or `false` if the bounded queue is full/closed.
    pub fn notify(
        &self,
        kind: AlertEventKind,
        request_id: &str,
        client_ip: &str,
        code: &str,
    ) -> bool {
        let payload = AlertPayload::build(kind, request_id, client_ip, code, &self.pepper);
        match self.tx.try_send(payload) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!(
                    alert_event = kind.as_str(),
                    "alert queue full (capacity {}); dropping alert without blocking request",
                    ALERT_CHANNEL_CAPACITY
                );
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::warn!(
                    alert_event = kind.as_str(),
                    "alert worker channel closed; dropping alert"
                );
                false
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    fn test_pepper() -> SecretString {
        SecretString::from("test-pepper-at-least-32-characters-long-12345")
    }

    #[test]
    fn builds_sanitized_payload_and_formats_all_webhooks() {
        let payload = AlertPayload::build(
            AlertEventKind::AuthBruteforce,
            "req-12345\nINJECTED",
            "203.0.113.42",
            "ACCOUNT_LOCKED",
            &test_pepper(),
        );

        assert_eq!(payload.event, "auth_bruteforce");
        assert_eq!(payload.severity, "high");
        assert_eq!(payload.ip_hash.len(), 16);
        assert!(!payload.ip_hash.contains("203.0.113.42"));
        assert!(!payload.request_id.contains('\n'));
        assert_eq!(payload.code, "ACCOUNT_LOCKED");

        let generic = format_webhook_body(&payload, WebhookFormat::Generic);
        assert_eq!(generic["event"], "auth_bruteforce");
        assert_eq!(generic["code"], "ACCOUNT_LOCKED");

        let discord = format_webhook_body(&payload, WebhookFormat::Discord);
        assert!(discord["content"].as_str().unwrap().contains("HIGH"));
        assert_eq!(discord["embeds"].as_array().unwrap().len(), 1);

        let slack = format_webhook_body(&payload, WebhookFormat::Slack);
        assert!(
            slack["text"]
                .as_str()
                .unwrap()
                .contains("event=auth_bruteforce")
        );
    }

    #[tokio::test]
    async fn http_webhook_sink_delivers_payload_to_local_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<String>();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = socket.read(&mut buf).await.unwrap();
            let raw = String::from_utf8_lossy(&buf[..n]).into_owned();
            let _ = socket
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await;
            let _ = done_tx.send(raw);
        });

        let url = SecretString::from(format!("http://{addr}/webhook"));
        let svc =
            AlertService::from_webhook_config(Some(url), WebhookFormat::Generic, test_pepper());

        assert!(svc.notify(
            AlertEventKind::CryptoIntegrityFailure,
            "req-crypto-1",
            "198.51.100.7",
            "INTERNAL_ERROR",
        ));

        let received = tokio::time::timeout(Duration::from_secs(3), done_rx)
            .await
            .unwrap()
            .unwrap();
        assert!(received.contains("crypto_integrity_failure"));
        assert!(received.contains("req-crypto-1"));
        assert!(!received.contains("198.51.100.7"));
    }

    #[tokio::test]
    async fn notify_never_blocks_when_webhook_stalls() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Accept connection and intentionally stall without sending a response.
        tokio::spawn(async move {
            if let Ok((_socket, _)) = listener.accept().await {
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });

        let sink = Arc::new(
            HttpWebhookSink::new(
                SecretString::from(format!("http://{addr}/slow")),
                WebhookFormat::Generic,
            )
            .unwrap(),
        );
        let svc = AlertService::spawn_with_timeout(sink, test_pepper(), Duration::from_millis(150));

        let started = std::time::Instant::now();
        let queued = svc.notify(
            AlertEventKind::Http5xx,
            "req-slow-1",
            "198.51.100.9",
            "INTERNAL_ERROR",
        );
        assert!(queued);
        assert!(started.elapsed() < Duration::from_millis(100));
    }
}
