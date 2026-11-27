-- =============================================================================
-- SecurityVault — Migración inicial del esquema (PostgreSQL 16+ / Neon)
-- Archivo: backend/migrations/0001_initial_schema.sql
-- Referencia: ADR-0001 (Neon PostgreSQL 16+, TLS verify-full, AES-256-GCM)
--
-- Notas operativas:
-- - Ejecutar con el rol propietario (p. ej. neondb_owner), NUNCA con securityvault_app.
-- - Todos los timestamps se almacenan en TIMESTAMPTZ (UTC).
-- - Los UUID de clave primaria los genera la aplicación antes del INSERT para
--   vincular record_id en el AAD de AES-256-GCM.
-- - Compatible con sqlx::migrate! (sin BEGIN/COMMIT explícitos) y Neon SQL Editor.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. Usuarios y estado MFA / bloqueo temporal
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL CHECK (length(btrim(email)) > 0),
    password_hash TEXT NOT NULL CHECK (length(password_hash) > 0),
    totp_secret_ciphertext BYTEA NOT NULL CHECK (octet_length(totp_secret_ciphertext) > 0),
    totp_secret_nonce BYTEA NOT NULL CHECK (octet_length(totp_secret_nonce) = 12),
    totp_key_version SMALLINT NOT NULL CHECK (totp_key_version >= 1),
    totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    failed_login_attempts SMALLINT NOT NULL DEFAULT 0 CHECK (failed_login_attempts >= 0),
    locked_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Unicidad insensible a mayúsculas/minúsculas sobre el correo electrónico
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lower
    ON users (LOWER(email));

-- Soporte para rotación gradual de secretos TOTP en rotate_keys (totp_key_version < active)
CREATE INDEX IF NOT EXISTS idx_users_totp_key_version
    ON users (totp_key_version);

-- -----------------------------------------------------------------------------
-- 2. Códigos de recuperación TOTP (8 códigos de un solo uso hasheados SHA-256)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS totp_recovery_codes (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash BYTEA NOT NULL CHECK (octet_length(code_hash) = 32),
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_totp_recovery_codes_user_id
    ON totp_recovery_codes (user_id);

CREATE UNIQUE INDEX IF NOT EXISTS uq_totp_recovery_codes_user_code_hash
    ON totp_recovery_codes (user_id, code_hash);

-- -----------------------------------------------------------------------------
-- 3. Sesiones opacas en servidor (tokens y CSRF almacenados solo como SHA-256)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    csrf_token_hash BYTEA NOT NULL CHECK (octet_length(csrf_token_hash) = 32),
    mfa_verified BOOLEAN NOT NULL DEFAULT FALSE,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id
    ON sessions (user_id);

CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
    ON sessions (expires_at);

-- -----------------------------------------------------------------------------
-- 4. Notas privadas cifradas con AES-256-GCM + AAD y versionado key_version
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS notes (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    category TEXT NOT NULL CHECK (
        category IN ('general', 'personal', 'finanzas', 'credenciales', 'documentos')
    ),
    title_ciphertext BYTEA NOT NULL CHECK (octet_length(title_ciphertext) > 0),
    title_nonce BYTEA NOT NULL CHECK (octet_length(title_nonce) = 12),
    content_ciphertext BYTEA NOT NULL CHECK (octet_length(content_ciphertext) > 0),
    content_nonce BYTEA NOT NULL CHECK (octet_length(content_nonce) = 12),
    key_version SMALLINT NOT NULL CHECK (key_version >= 1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Listado paginado de notas de un usuario ordenadas de más reciente a más antigua
CREATE INDEX IF NOT EXISTS idx_notes_user_created_at
    ON notes (user_id, created_at DESC);

-- Listado paginado filtrado por categoría para un usuario
CREATE INDEX IF NOT EXISTS idx_notes_user_category_created_at
    ON notes (user_id, category, created_at DESC);

-- Búsqueda eficiente de lotes pendientes durante la rotación de llaves (rotate_keys)
CREATE INDEX IF NOT EXISTS idx_notes_key_version
    ON notes (key_version);

-- -----------------------------------------------------------------------------
-- 5. Registro de intentos de autenticación (anti fuerza bruta y alertas)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS auth_attempts (
    id UUID PRIMARY KEY,
    identifier_hash BYTEA NOT NULL CHECK (octet_length(identifier_hash) = 32),
    ip_hash BYTEA NOT NULL CHECK (octet_length(ip_hash) = 32),
    attempt_type TEXT NOT NULL CHECK (attempt_type IN ('login', 'totp', 'recovery')),
    succeeded BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_attempts_identifier_created_at
    ON auth_attempts (identifier_hash, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_auth_attempts_ip_created_at
    ON auth_attempts (ip_hash, created_at DESC);
