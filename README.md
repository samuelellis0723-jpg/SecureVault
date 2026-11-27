# SecurityVault

Bóveda web personal y multiusuario para guardar notas privadas y datos sensibles, diseñada desde cero con foco en **OWASP Top 10:2025**, criptografía aplicada y despliegue seguro en un único contenedor Docker no-root.

## Arquitectura general

- **Backend (`backend/`):** Rust (`edition = "2024"`) + Axum + Tokio + Tower + SQLx (`rustls`) con lints estrictos (`unsafe_code = "forbid"`, `unwrap_used = "deny"`, `expect_used = "deny"`, `panic = "deny"`).
- **Frontend (`frontend/`):** React + Vite + JavaScript + React Router + CSS vanilla accesible (WCAG 2.2 AA), compilado en build multi-etapa y servido desde el mismo origen mediante `tower_http::services::ServeDir` con fallback SPA.
- **Base de datos:** PostgreSQL 16+ (Neon en producción) con TLS obligatorio (`sslmode=verify-full`), consultas 100% parametrizadas (`$1, $2`) y rol SQL de mínimo privilegio (`securityvault_app` solo DML).
- **Empaquetado y CI/CD:** `Dockerfile` multi-etapa no-root (`appuser`, UID `10001`) y pipeline en `.github/workflows/ci.yml` (`gitleaks`, `rustfmt`, `clippy`, `cargo test` contra `postgres:16`, prueba de mínimo privilegio SQL, `cargo audit`, `cargo deny`, Jest/RTL, `npm audit` y verificación Docker no-root).

## Controles de seguridad clave

- **Autenticación y MFA obligatorio:** Contraseñas con **Argon2id** (`spawn_blocking`), **TOTP RFC 6238** obligatorio con código QR SVG y 8 códigos de recuperación de un solo uso hasheados, sesiones opacas en PostgreSQL (`HttpOnly; Secure; SameSite=Strict`, 30 min inactividad / 8 h absoluta), rotación tras MFA y protección CSRF (`X-CSRF-Token`).
- **Cifrado en reposo y rotación sin caída:** Notas y secretos TOTP cifrados con **AES-256-GCM** + nonces aleatorios de 96 bits + **AAD** ligado a `key_version`, `user_id` y `record_id`, llaves protegidas con `secrecy`/`zeroize` y CLI idempotente `rotate_keys`.
- **Aislamiento y endurecimiento HTTP:** Aislamiento estricto por `user_id` (anti-BOLA), cabeceras CSP/HSTS/nosniff/DENY/Referrer-Policy/Permissions-Policy, `Cache-Control: no-store` en `/api/v1/*`, `#[serde(deny_unknown_fields)]`, límites de tamaño/timeout/rate-limit y alertas externas saneadas vía webhook (`generic`, `discord`, `slack`).

## Estructura del repositorio

```text
SecurityVault/
├── backend/                     # API Rust/Axum, migraciones SQLx y CLIs (migrate, rotate_keys)
│   ├── migrations/              # 0001_initial_schema.sql
│   ├── sql/                     # 00_least_privilege_role.sql
│   ├── src/                     # config, crypto, domain, repositories, services, http, bin/
│   └── tests/                   # api_integration.rs (oneshot) y pg_integration.rs (CI postgres:16)
├── frontend/                    # SPA React + Vite + Jest/RTL
├── docs/
│   └── GUIA-DESPLIEGUE-PRINCIPIANTES.md
├── .github/workflows/ci.yml     # Pipeline completo de seguridad, pruebas y Docker
├── Dockerfile                   # Build multi-etapa no-root (React + Rust -> debian:bookworm-slim)
├── .dockerignore
└── .env.example
```

## Inicio rápido local

1. Copia `.env.example` a `.env` y completa `DATABASE_URL`, `VAULT_KEY_V1` (64 hex) y `SECURITY_PEPPER` (≥ 32 caracteres).
2. Aplica las migraciones contra tu PostgreSQL local o de desarrollo:
   ```bash
   export PATH="$HOME/.cargo/bin:$PATH"
   DATABASE_URL="postgresql://..." cargo run --manifest-path backend/Cargo.toml --bin migrate
   ```
3. Inicia el backend en `:8080`:
   ```bash
   export PATH="$HOME/.cargo/bin:$PATH"
   cd backend && cargo run --bin securityvault
   ```
4. En otra terminal, inicia el frontend Vite en `:5173` (con proxy automático a `/api` y `/healthz`):
   ```bash
   cd frontend && npm ci && npm run dev
   ```

## Comandos de verificación

```bash
# Backend Rust
export PATH="$HOME/.cargo/bin:$PATH"
cd backend
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo audit
cargo deny check

# Frontend React
cd ../frontend
npm test
npm run build
npm audit --audit-level=high
```

## Despliegue en producción (Neon + Render)

Consulta la guía paso a paso para principiantes en [`docs/GUIA-DESPLIEGUE-PRINCIPIANTES.md`](docs/GUIA-DESPLIEGUE-PRINCIPIANTES.md) para crear la base de datos en Neon, aprovisionar el rol `securityvault_app`, generar llaves, configurar alertas por webhook, desplegar en Render con Docker y rotar llaves sin downtime.
