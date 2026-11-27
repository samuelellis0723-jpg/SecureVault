# Guía de Despliegue para Principiantes — SecurityVault (Neon + Render + Docker)

Esta guía te lleva **paso a paso desde cero** para publicar **SecurityVault** en producción de forma segura y gratuita usando **Neon PostgreSQL**, un **webhook de alertas** (Discord o `webhook.site`) y **Render** con Docker.

> **No necesitas instalar Docker en tu computadora:** Render construye automáticamente el `Dockerfile` del repositorio en la nube y te entrega HTTPS gestionado.

---

## Requisitos previos

- Cuenta en **GitHub** con el repositorio `SecurityVault` subido.
- **Node.js** instalado localmente (solo lo usaremos para generar llaves criptográficas aleatorias con `crypto.randomBytes`).
- Opcional: **Rust / Cargo** si deseas ejecutar `migrate` o `rotate_keys` desde tu terminal local.
- Un gestor de contraseñas (Bitwarden, 1Password, KeePassXC, etc.) para guardar tus secretos **fuera del repositorio**.

---

## Paso 1 — Crear tu base de datos gratuita en Neon PostgreSQL

1. Entra a [https://neon.tech](https://neon.tech) y crea una cuenta gratuita (puedes iniciar sesión con GitHub).
2. Haz clic en **"Create a project"**:
   - **Project name:** `securityvault`
   - **Postgres version:** `16` (o superior estable)
   - **Region:** elige la más cercana a la región que usarás en Render (por ejemplo, `US East (Ohio)` o `US East (N. Virginia)`).
3. Al crearse el proyecto, Neon te mostrará la **Connection String** del rol propietario (`neondb_owner`), parecida a:
   ```text
   postgresql://neondb_owner:TU_PASSWORD@ep-xxxx.us-east-2.aws.neon.tech/neondb?sslmode=require
   ```
4. **Guárdala en tu gestor de contraseñas** (nunca en `.env` versionado ni en Git).
5. **Importante (TLS estricto):** Cuando uses esta URL con SecurityVault, cambia `sslmode=require` por **`sslmode=verify-full`**. En producción, el backend rechaza arrancar si falta `sslmode=verify-full`.

---

## Paso 2 — Aplicar la migración inicial (`0001_initial_schema.sql`)

Las tablas deben crearse usando el rol propietario (`neondb_owner`). Tienes dos opciones:

### Opción A — Directamente desde el navegador (más fácil)
1. En el panel de Neon, abre **SQL Editor** en el menú izquierdo.
2. Abre el archivo `backend/migrations/0001_initial_schema.sql` de este repositorio, copia todo su contenido y pégalo en el editor SQL de Neon.
3. Haz clic en **Run** y verifica que termine sin errores.

### Opción B — Desde tu terminal local con el binario `migrate`
```bash
export PATH="$HOME/.cargo/bin:$PATH"
DATABASE_URL="postgresql://neondb_owner:TU_PASSWORD@ep-xxxx.us-east-2.aws.neon.tech/neondb?sslmode=verify-full" \
  cargo run --manifest-path backend/Cargo.toml --bin migrate
```
Deberías ver: `SecurityVault migrations applied successfully.`

---

## Paso 3 — Crear el usuario de mínimo privilegio (`securityvault_app`)

Por seguridad (OWASP A02/A05), la aplicación web **nunca debe conectarse como `neondb_owner`** (que puede borrar o alterar tablas). En su lugar crearemos `securityvault_app`, que solo tiene permisos `SELECT, INSERT, UPDATE, DELETE` sobre las 5 tablas de la app:

1. Genera una contraseña aleatoria fuerte en tu terminal local (mínimo 20 caracteres):
   ```bash
   node -e "console.log(require('crypto').randomBytes(24).toString('base64url'))"
   ```
2. Guarda esa contraseña en tu gestor de contraseñas.
3. Abre **SQL Editor** en Neon (conectado como `neondb_owner`).
4. Copia todo el contenido de `backend/sql/00_least_privilege_role.sql` y pégalo en el editor.
5. Busca la línea:
   ```sql
   v_password CONSTANT TEXT := 'CAMBIA_ESTA_CONTRASENA_FUERTE';
   ```
   y reemplaza `CAMBIA_ESTA_CONTRASENA_FUERTE` por la contraseña aleatoria que generaste.
6. Presiona **Run**.
7. (Opcional recomendado) Ejecuta esta consulta de verificación en Neon SQL Editor para confirmar que `securityvault_app` no puede crear tablas:
   ```sql
   SELECT has_schema_privilege('securityvault_app', 'public', 'CREATE') AS can_create_in_public,
          has_schema_privilege('securityvault_app', 'public', 'USAGE') AS can_use_public;
   ```
   Resultado esperado: `can_create_in_public = false`, `can_use_public = true`.
8. Construye tu **`DATABASE_URL` de producción para Render** reemplazando usuario y contraseña por `securityvault_app` y asegurando `?sslmode=verify-full`:
   ```text
   postgresql://securityvault_app:TU_CONTRASENA_DE_APP@ep-xxxx.us-east-2.aws.neon.tech/neondb?sslmode=verify-full
   ```

---

## Paso 4 — Generar las llaves secretas de cifrado y pepper

Ejecuta estos dos comandos en tu terminal local y guarda los resultados **solo en tu gestor de contraseñas**:

```bash
# 1) Llave maestra AES-256-GCM versión 1 (64 caracteres hex exactos = 32 bytes)
node -e "console.log('VAULT_KEY_V1=' + require('crypto').randomBytes(32).toString('hex'))"

# 2) Pepper criptográfico para códigos de recuperación y hash de IPs/identificadores (64 hex)
node -e "console.log('SECURITY_PEPPER=' + require('crypto').randomBytes(32).toString('hex'))"
```

> **Advertencia:** Si pierdes `VAULT_KEY_V1`, las notas cifradas con versión 1 no podrán descifrarse. Haz una copia segura de respaldo en tu gestor de contraseñas.

---

## Paso 5 — Configurar el webhook de alertas de seguridad (gratis)

SecurityVault envía alertas saneadas (sin contraseñas, sin correos ni contenido de notas) cuando detecta:
- ≥ 5 intentos fallidos de login/TOTP en 15 minutos (`auth_bruteforce`),
- errores HTTP 5xx inesperados (`http_5xx`), o
- fallos de integridad criptográfica AEAD (`crypto_integrity_failure`).

Elige una de estas opciones:

- **Opción A — Discord (recomendada para uso continuo):**
  1. Crea un servidor privado en Discord y un canal (por ejemplo `#alertas-vault`).
  2. Haz clic en el engranaje del canal (**Editar canal**) → **Integraciones** → **Webhooks** → **Nuevo Webhook** → **Copiar URL del webhook**.
  3. En Render usarás `ALERT_WEBHOOK_FORMAT=discord`.
- **Opción B — Prueba rápida sin cuentas (`webhook.site`):**
  1. Abre [https://webhook.site](https://webhook.site) y copia **"Your unique URL"**.
  2. En Render usarás `ALERT_WEBHOOK_FORMAT=generic`.
- **Opción C — Slack:**
  1. Crea un Incoming Webhook en tu workspace de Slack.
  2. En Render usarás `ALERT_WEBHOOK_FORMAT=slack`.

---

## Paso 6 — Crear cuenta en Render y desplegar con Docker

1. Entra a [https://render.com](https://render.com) y crea una cuenta gratuita con **"Sign in with GitHub"**.
2. En el Dashboard haz clic en **"New +"** → **"Web Service"**.
3. Conecta y selecciona tu repositorio `SecurityVault`.
4. Configura el servicio:
   - **Name:** `securityvault` *(Render te asignará una URL como `https://securityvault.onrender.com`)*
   - **Region:** la misma (o más cercana) que elegiste en Neon.
   - **Language / Runtime:** **`Docker`** *(Render detecta automáticamente el `Dockerfile` en la raíz)*.
   - **Instance Type:** **`Free`** *(el binario en Rust consume muy poca memoria RAM)*.
   - En **Advanced → Health Check Path:** `/healthz`
5. En la sección **Environment Variables**, añade una por una:

   | Variable | Valor |
   |---|---|
   | `APP_ENV` | `production` |
   | `PORT` | `8080` |
   | `APP_ORIGIN` | `https://tu-servicio.onrender.com` *(cámbialo por tu URL exacta de Render, sin barra final)* |
   | `ALLOW_REGISTRATION` | `true` *(cámbialo a `false` tras crear tu cuenta si quieres cerrar el registro)* |
   | `DATABASE_URL` | `postgresql://securityvault_app:...@ep-xxxx.neon.tech/neondb?sslmode=verify-full` |
   | `VAULT_ACTIVE_KEY_VERSION` | `1` |
   | `VAULT_KEY_V1` | *(los 64 caracteres hex del Paso 4)* |
   | `SECURITY_PEPPER` | *(los 64 caracteres hex del Paso 4)* |
   | `ALERT_WEBHOOK_URL` | *(tu URL `https://...` de Discord, Slack o webhook.site)* |
   | `ALERT_WEBHOOK_FORMAT` | `discord` *(o `slack` / `generic`)* |

   > Nota: `STATIC_DIR=/app/static` y `RUST_LOG=info` ya vienen preconfigurados dentro del `Dockerfile`.

6. Haz clic en **"Deploy Web Service"**.
   - El primer build compila el frontend React/Vite y el backend Rust (~4 a 7 minutos).
   - Cuando el estado cambie a **Live**, tu bóveda ya estará publicada con HTTPS automático.

---

## Paso 7 — Verificación post-despliegue

1. **Comprobar salud (`/healthz`):**
   Abre `https://<tu-servicio>.onrender.com/healthz` en el navegador. Debe responder:
   ```json
   {"status":"ok"}
   ```
2. **Registro + MFA TOTP + primera nota:**
   - Abre `https://<tu-servicio>.onrender.com`.
   - Crea tu cuenta con una contraseña fuerte (≥ 12 caracteres).
   - Escanea el código QR con Google Authenticator, Authy, 2FAS o Ente Auth e introduce el código de 6 dígitos para confirmar.
   - **Guarda los 8 códigos de recuperación** que se muestran una sola vez en tu gestor de contraseñas.
   - Crea una nota de prueba, recarga la página en `/vault` (verifica que la ruta SPA carga correctamente) y confirma que la nota se lee y edita sin errores.
3. **Cerrar registro (opcional recomendado para uso personal):**
   - En Render → **Environment**, cambia `ALLOW_REGISTRATION` de `true` a `false` y guarda para redesplegar.
4. **Probar el bloqueo y la alerta por webhook:**
   - Abre una ventana de incógnito e intenta iniciar sesión con tu correo y una contraseña incorrecta **5 veces seguidas**.
   - Al 5.º intento la API responderá `429 ACCOUNT_LOCKED` (bloqueo de 15 minutos) y recibirás una alerta en tu canal de Discord / `webhook.site`.
   - Verifica que la alerta **no contiene** tu correo, contraseña ni IP en texto claro.

---

## Paso 8 — Cómo rotar llaves de cifrado sin downtime (`VAULT_KEY_V1` → `VAULT_KEY_V2`)

SecurityVault almacena la columna `key_version` junto a cada nota y secreto TOTP para permitir rotación gradual sin caída del servicio:

1. **Genera la nueva llave versión 2:**
   ```bash
   node -e "console.log('VAULT_KEY_V2=' + require('crypto').randomBytes(32).toString('hex'))"
   ```
   Guárdala en tu gestor de contraseñas.
2. **Despliega con ambas llaves en Render:**
   - En Render → **Environment**, agrega `VAULT_KEY_V2` y cambia `VAULT_ACTIVE_KEY_VERSION` de `1` a `2`.
   - **NO borres todavía `VAULT_KEY_V1`**.
   - Render redesplegará: todas las notas nuevas se cifrarán con `v2` y las anteriores seguirán leyéndose con `v1`.
3. **Re-cifra los registros antiguos en lotes idempotentes:**
   Ejecuta el binario `rotate_keys` desde tu terminal local con las mismas variables (`DATABASE_URL`, `VAULT_KEY_V1`, `VAULT_KEY_V2`, `VAULT_ACTIVE_KEY_VERSION=2`, `SECURITY_PEPPER`, `APP_ENV=production`, `APP_ORIGIN`):
   ```bash
   export PATH="$HOME/.cargo/bin:$PATH"
   APP_ENV=production \
   APP_ORIGIN="https://tu-servicio.onrender.com" \
   DATABASE_URL="postgresql://securityvault_app:...@ep-xxxx.neon.tech/neondb?sslmode=verify-full" \
   VAULT_ACTIVE_KEY_VERSION=2 \
   VAULT_KEY_V1="<tu_llave_v1_64_hex>" \
   VAULT_KEY_V2="<tu_llave_v2_64_hex>" \
   SECURITY_PEPPER="<tu_pepper>" \
     cargo run --manifest-path backend/Cargo.toml --bin rotate_keys
   ```
   Verás un resumen sin datos sensibles:
   ```text
   Key rotation complete: active_key_version=2, notes_rotated=..., users_rotated=...
   ```
4. **Confirma que no queden registros en `v1`:**
   Vuelve a ejecutar el mismo comando; debe reportar `notes_rotated=0, users_rotated=0`.
5. **Retira `VAULT_KEY_V1` de Render:**
   Ahora sí puedes eliminar `VAULT_KEY_V1` en Render → **Environment** y redesplegar. Tus notas y secretos TOTP seguirán funcionando exclusivamente con `VAULT_KEY_V2`.

---

## Solución rápida de problemas comunes

| Error al arrancar en Render | Causa probable | Solución |
|---|---|---|
| `DATABASE_URL: production requires sslmode=verify-full` | La URL de Neon tiene `sslmode=require` o sin `sslmode` | Cambia el final de `DATABASE_URL` a `?sslmode=verify-full`. |
| `VAULT_KEY_V1: must be exactly 64 valid hexadecimal characters` | La llave tiene espacios o menos/más de 64 caracteres | Vuelve a generarla con `crypto.randomBytes(32).toString('hex')`. |
| `APP_ORIGIN: must use https:// in production` | Usaste `http://` o dejaste `APP_ORIGIN` vacío | Pon la URL exacta `https://<tu-app>.onrender.com`. |
| `permission denied for table ...` | Faltó ejecutar `00_least_privilege_role.sql` o las tablas se crearon después | Ejecuta `0001_initial_schema.sql` y luego `00_least_privilege_role.sql` como `neondb_owner`. |
| `403 CSRF_INVALID` desde el navegador | `APP_ORIGIN` no coincide con el dominio real | Verifica que `APP_ORIGIN` coincida exactamente con la URL del navegador (sin `/` al final). |
