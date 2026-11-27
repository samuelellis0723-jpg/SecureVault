-- =============================================================================
-- SecurityVault — Aprovisionamiento de rol de mínimo privilegio (PostgreSQL 16+)
-- Archivo: backend/sql/00_least_privilege_role.sql
--
-- INSTRUCCIONES PARA NEON SQL EDITOR (ejecutar como neondb_owner):
-- 1. Aplica primero la migración inicial:
--      backend/migrations/0001_initial_schema.sql
-- 2. Genera una contraseña aleatoria fuerte en tu terminal local (NO la subas a Git):
--      node -e "console.log(require('crypto').randomBytes(24).toString('base64url'))"
-- 3. Reemplaza el valor CAMBIA_ESTA_CONTRASENA_FUERTE abajo por la contraseña
--    generada (mínimo 20 caracteres).
-- 4. Pega y ejecuta este script completo en Neon SQL Editor usando el rol propietario.
-- 5. En Render, configura DATABASE_URL con este rol y TLS estricto:
--      postgresql://securityvault_app:<TU_CONTRASENA>@<HOST_NEON>/<DB>?sslmode=verify-full
--
-- Principio de mínimo privilegio (OWASP A02 / A05):
-- - securityvault_app SOLO obtiene USAGE en public y SELECT, INSERT, UPDATE, DELETE
--   sobre las 5 tablas de dominio.
-- - CERO permisos DDL (CREATE, ALTER, DROP, TRUNCATE, REFERENCES, TRIGGER).
-- - SIN acceso a _sqlx_migrations (reservada para el rol propietario de migraciones).
-- =============================================================================

-- 1. Crear o actualizar el rol de aplicación sin privilegios administrativos
DO $$
DECLARE
    v_password CONSTANT TEXT := 'CAMBIA_ESTA_CONTRASENA_FUERTE';
BEGIN
    IF v_password = ('CAMBIA_' || 'ESTA_CONTRASENA_FUERTE') OR length(v_password) < 20 THEN
        RAISE EXCEPTION 'Debes reemplazar el placeholder por una contraseña aleatoria de al menos 20 caracteres antes de ejecutar este script.';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'securityvault_app') THEN
        EXECUTE format(
            'CREATE ROLE securityvault_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD %L',
            v_password
        );
    ELSE
        EXECUTE format(
            'ALTER ROLE securityvault_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD %L',
            v_password
        );
    END IF;
END
$$;

-- 2. Endurecimiento de parámetros por sesión del rol de aplicación
ALTER ROLE securityvault_app SET search_path = public;
ALTER ROLE securityvault_app SET timezone = 'UTC';
ALTER ROLE securityvault_app SET statement_timeout = '10s';
ALTER ROLE securityvault_app SET idle_in_transaction_session_timeout = '15s';

-- 3. Revocar permisos DDL en el esquema public a PUBLIC y limpiar permisos previos del rol
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM securityvault_app;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM securityvault_app;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM securityvault_app;

-- 4. Otorgar conexión a la base de datos actual y USAGE (sin CREATE) en public
DO $$
BEGIN
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO securityvault_app', current_database());
END
$$;

GRANT USAGE ON SCHEMA public TO securityvault_app;

-- 5. Otorgar ÚNICAMENTE DML mínimo (SELECT, INSERT, UPDATE, DELETE) sobre las 5 tablas
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
    public.users,
    public.totp_recovery_codes,
    public.sessions,
    public.notes,
    public.auth_attempts
TO securityvault_app;

-- =============================================================================
-- CONSULTAS DE VERIFICACIÓN MANUAL (ejecutar por separado tras aplicar el script)
-- =============================================================================
-- -- Confirmar atributos del rol (esperado: rolcanlogin=t, rolsuper=f, rolcreatedb=f, rolcreaterole=f, rolinherit=f):
-- SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolinherit
-- FROM pg_catalog.pg_roles
-- WHERE rolname = 'securityvault_app';
--
-- -- Confirmar que solo existen SELECT, INSERT, UPDATE, DELETE sobre las 5 tablas:
-- SELECT table_schema, table_name, privilege_type
-- FROM information_schema.role_table_grants
-- WHERE grantee = 'securityvault_app'
-- ORDER BY table_name, privilege_type;
--
-- -- Confirmar que securityvault_app NO tiene CREATE sobre el esquema public (esperado: false):
-- SELECT has_schema_privilege('securityvault_app', 'public', 'CREATE') AS can_create_in_public,
--        has_schema_privilege('securityvault_app', 'public', 'USAGE') AS can_use_public;
