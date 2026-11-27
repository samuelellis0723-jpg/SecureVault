//! Live PostgreSQL integration test executed automatically in CI when `TEST_DATABASE_URL` is set.
//!
//! When `TEST_DATABASE_URL` is absent (e.g., local environments without Docker/PostgreSQL),
//! the test returns early without failing.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use secrecy::{ExposeSecret, SecretString};
use sqlx::{Row, migrate::Migrator};
use uuid::Uuid;
use zeroize::Zeroizing;

use security_vault_backend::{
    crypto::cipher::{KEY_LEN, KeyRing},
    domain::{error::AppError, models::NoteCategory},
    repositories::{VaultRepositories, pg::PgStore},
    services::{
        alerts::{AlertService, RecordingAlertSink},
        auth::AuthService,
        notes::NotesService,
        rotation::rotate_all_keys,
    },
};

fn make_key_ring(active_version: i16, versions: &[(i16, u8)]) -> KeyRing {
    let mut keys = HashMap::new();
    for &(ver, byte) in versions {
        keys.insert(ver, Zeroizing::new([byte; KEY_LEN]));
    }
    KeyRing::new(active_version, keys).unwrap()
}

#[tokio::test]
async fn pg_end_to_end_migrations_auth_notes_bola_rotation_and_delete() {
    let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else {
        return;
    };
    if db_url.trim().is_empty() {
        return;
    }

    let pg_store = Arc::new(
        PgStore::connect(&SecretString::from(db_url), false)
            .await
            .expect("failed to connect to TEST_DATABASE_URL"),
    );

    // 1. Run real SQLx migrations (0001_initial_schema.sql)
    let migrations_dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations"));
    let migrator = Migrator::new(migrations_dir)
        .await
        .expect("failed to load backend/migrations");
    migrator
        .run(pg_store.pool())
        .await
        .expect("failed to apply SQLx migrations");

    let repos = VaultRepositories::from_pg(Arc::clone(&pg_store));
    let pepper = SecretString::from("pg-integration-test-security-pepper-minimum-32-chars");
    let sink = Arc::new(RecordingAlertSink::new());
    let alerts = AlertService::spawn(sink, pepper.clone());

    let ring_v1 = make_key_ring(1, &[(1, 0x11)]);
    let auth_v1 = AuthService::new(
        repos.clone(),
        ring_v1.clone(),
        pepper.clone(),
        true,
        alerts.clone(),
    );
    let notes_v1 = NotesService::new(repos.clone(), ring_v1, alerts.clone());

    // 2. Register Alice and Bob (direct full sessions in PostgreSQL without TOTP step)
    let run_id = Uuid::new_v4();
    let alice_email = format!("pg-alice-{run_id}@example.com");
    let bob_email = format!("pg-bob-{run_id}@example.com");

    let reg_alice = auth_v1
        .register(&alice_email, SecretString::from("AlicePgStrongPass#2026"))
        .await
        .unwrap();
    let alice_id = reg_alice.user.id;

    let full_session_alice = auth_v1
        .authenticate_session(reg_alice.session_token.expose_secret())
        .await
        .unwrap();
    assert!(full_session_alice.session.mfa_verified);
    assert_eq!(full_session_alice.session.user_id, alice_id);

    // Standard login also opens a full session immediately
    let login_alice = auth_v1
        .login(
            &alice_email,
            SecretString::from("AlicePgStrongPass#2026"),
            "127.0.0.1",
            "pg-test-login-1",
        )
        .await
        .unwrap();
    assert_eq!(login_alice.user.id, alice_id);
    let login_session_alice = auth_v1
        .authenticate_session(login_alice.session_token.expose_secret())
        .await
        .unwrap();
    assert!(login_session_alice.session.mfa_verified);

    let reg_bob = auth_v1
        .register(&bob_email, SecretString::from("BobPgStrongPass#2026!"))
        .await
        .unwrap();
    let bob_id = reg_bob.user.id;

    // 3. Create encrypted note for Alice and verify raw bytes in PostgreSQL contain no plaintext
    let secret_title = "Clave Banco PG";
    let secret_content = "dato-altamente-confidencial-en-postgresql-2026";
    let created_note = notes_v1
        .create_note(
            alice_id,
            secret_title,
            secret_content,
            NoteCategory::Finanzas,
        )
        .await
        .unwrap();
    assert_eq!(created_note.key_version, 1);

    let raw_row = sqlx::query(
        "SELECT title_ciphertext, content_ciphertext, key_version FROM notes WHERE id = $1",
    )
    .bind(created_note.id)
    .fetch_one(pg_store.pool())
    .await
    .unwrap();
    let title_ct: Vec<u8> = raw_row.try_get("title_ciphertext").unwrap();
    let content_ct: Vec<u8> = raw_row.try_get("content_ciphertext").unwrap();
    let stored_ver: i16 = raw_row.try_get("key_version").unwrap();
    assert_eq!(stored_ver, 1);
    assert!(
        !title_ct
            .windows(secret_title.len())
            .any(|w| w == secret_title.as_bytes())
    );
    assert!(
        !content_ct
            .windows(secret_content.len())
            .any(|w| w == secret_content.as_bytes())
    );

    // 4. Verify strict user_id BOLA isolation in PostgreSQL
    let get_by_bob = notes_v1
        .get_note(bob_id, created_note.id, "127.0.0.1", "pg-test-bola-1")
        .await;
    assert!(matches!(get_by_bob, Err(AppError::NotFound)));

    let update_by_bob = notes_v1
        .update_note(
            bob_id,
            created_note.id,
            Some("Interceptado"),
            None,
            None,
            "127.0.0.1",
            "pg-test-bola-2",
        )
        .await;
    assert!(matches!(update_by_bob, Err(AppError::NotFound)));

    let delete_by_bob = notes_v1.delete_note(bob_id, created_note.id).await;
    assert!(matches!(delete_by_bob, Err(AppError::NotFound)));

    let (bob_notes, bob_meta) = notes_v1
        .list_notes(bob_id, None, 1, 20, "127.0.0.1", "pg-test-bola-3")
        .await
        .unwrap();
    assert_eq!(bob_notes.len(), 0);
    assert_eq!(bob_meta.total, 0);

    // 5. Rotate keys v1 -> v2 against live PostgreSQL and verify idempotency + v2-only decryption
    let ring_v1_v2 = make_key_ring(2, &[(1, 0x11), (2, 0x22)]);
    let report = rotate_all_keys(&repos, &ring_v1_v2, 50).await.unwrap();
    assert_eq!(report.active_version, 2);
    assert!(report.notes_rotated >= 1);
    assert!(report.users_rotated >= 2);

    let report_idempotent = rotate_all_keys(&repos, &ring_v1_v2, 50).await.unwrap();
    assert_eq!(report_idempotent.notes_rotated, 0);
    assert_eq!(report_idempotent.users_rotated, 0);

    let ring_only_v2 = make_key_ring(2, &[(2, 0x22)]);
    let notes_v2 = NotesService::new(repos.clone(), ring_only_v2, alerts);
    let decrypted_v2 = notes_v2
        .get_note(alice_id, created_note.id, "127.0.0.1", "pg-test-v2-read")
        .await
        .unwrap();
    assert_eq!(decrypted_v2.title, secret_title);
    assert_eq!(decrypted_v2.content, secret_content);
    assert_eq!(decrypted_v2.key_version, 2);

    // 6. Update and delete note as Alice
    let updated = notes_v2
        .update_note(
            alice_id,
            created_note.id,
            Some("Clave Banco PG Actualizada"),
            None,
            Some(NoteCategory::Documentos),
            "127.0.0.1",
            "pg-test-patch",
        )
        .await
        .unwrap();
    assert_eq!(updated.title, "Clave Banco PG Actualizada");
    assert_eq!(updated.content, secret_content);
    assert_eq!(updated.category, NoteCategory::Documentos);

    notes_v2
        .delete_note(alice_id, created_note.id)
        .await
        .unwrap();
    let after_delete = notes_v2
        .get_note(alice_id, created_note.id, "127.0.0.1", "pg-test-gone")
        .await;
    assert!(matches!(after_delete, Err(AppError::NotFound)));

    // 7. Logout revokes session in PostgreSQL
    auth_v1.logout(&full_session_alice).await.unwrap();
    let after_logout = auth_v1
        .authenticate_session(reg_alice.session_token.expose_secret())
        .await;
    assert!(matches!(after_logout, Err(AppError::Unauthorized(_))));

    // 8. Clean up test rows (ON DELETE CASCADE removes sessions and notes)
    sqlx::query("DELETE FROM users WHERE id = ANY($1)")
        .bind([alice_id, bob_id])
        .execute(pg_store.pool())
        .await
        .unwrap();
}
