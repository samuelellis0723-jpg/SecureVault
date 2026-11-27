# =============================================================================
# SecurityVault — Multi-stage hardened Docker build (React/Vite + Rust/Axum)
# =============================================================================

# --- Stage 1: Build React/Vite SPA static bundle -----------------------------
FROM node:22-alpine AS frontend-builder
WORKDIR /frontend

COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# --- Stage 2: Build Rust Axum server + migrate + rotate_keys binaries --------
FROM rust:1-bookworm AS backend-builder
WORKDIR /backend

COPY backend/Cargo.toml backend/Cargo.lock ./
RUN mkdir -p src/bin \
    && printf 'pub fn _deps_cache() {}\n' > src/lib.rs \
    && printf 'fn main() {}\n' > src/main.rs \
    && printf 'fn main() {}\n' > src/bin/migrate.rs \
    && printf 'fn main() {}\n' > src/bin/rotate_keys.rs \
    && cargo build --release --locked --bin securityvault --bin migrate --bin rotate_keys \
    && rm -rf src

COPY backend/src ./src
COPY backend/migrations ./migrations
RUN touch src/lib.rs src/main.rs src/bin/migrate.rs src/bin/rotate_keys.rs \
    && cargo build --release --locked --bin securityvault --bin migrate --bin rotate_keys

# --- Stage 3: Minimal non-root runtime image ---------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 appuser \
    && useradd --uid 10001 --gid 10001 --home-dir /app --no-create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /app/static /app/migrations

WORKDIR /app

COPY --from=backend-builder /backend/target/release/securityvault /app/securityvault
COPY --from=backend-builder /backend/target/release/migrate /app/migrate
COPY --from=backend-builder /backend/target/release/rotate_keys /app/rotate_keys
COPY --from=backend-builder /backend/migrations /app/migrations
COPY --from=frontend-builder /frontend/dist /app/static

RUN chown -R root:root /app \
    && chmod 0555 /app /app/securityvault /app/migrate /app/rotate_keys \
    && find /app/static /app/migrations -type d -exec chmod 0555 {} + \
    && find /app/static /app/migrations -type f -exec chmod 0444 {} +

USER appuser

ENV APP_ENV=production \
    PORT=8080 \
    STATIC_DIR=/app/static \
    RUST_LOG=info

EXPOSE 8080

ENTRYPOINT ["/app/securityvault"]
