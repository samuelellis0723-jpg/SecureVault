# Adaptador de Entrada — Antigravity / Gemini CLI para SecurityVault

Lee y aplica íntegramente [cerebro/AGENTS.md](cerebro/AGENTS.md) y [cerebro/adaptadores/antigravity.md](cerebro/adaptadores/antigravity.md) como marco de trabajo principal.

## Arranque rápido

1. **Candado estricto de Git/GitHub:** No ejecutar comandos de Git (`commit`, `push`, `branch`, etc.) ni operaciones en GitHub sin orden expresa del usuario ([cerebro/reglas/comunes/git.md](cerebro/reglas/comunes/git.md)).
2. **Contexto operativo activo:** Lee [contexto.md](cerebro/memoria/operativa/proyectos/security-vault/contexto.md) para verificar el estado vivo y `modulos_activos` (MySQL 8+ por defecto; Supabase solo si está declarado expresamente).
3. **Divulgación progresiva:**
   - **Trivial:** 1 solo especialista directamente (sin plan ni spec).
   - **Estándar:** 1 especialista + validación con `@qa` con pruebas reales.
   - **Compleja:** `@orchestrator` (`grill-me` / `to-spec` → `planes-implementacion` → especialistas → `@qa` + `@security`).
4. **Evidencia:** Todo reporte emite veredicto `PASS`, `FAIL`, `BLOCKED` o `NOT TESTED` con salida de pruebas verificables.

## Los 6 Roles Disponibles

| Rol | Definición y Perfil |
|---|---|
| `@orchestrator` | [cerebro/agentes/orchestrator.md](cerebro/agentes/orchestrator.md) |
| `@backend` | [cerebro/agentes/backend.md](cerebro/agentes/backend.md) |
| `@frontend` | [cerebro/agentes/frontend.md](cerebro/agentes/frontend.md) |
| `@database` | [cerebro/agentes/database.md](cerebro/agentes/database.md) |
| `@qa` | [cerebro/agentes/qa.md](cerebro/agentes/qa.md) |
| `@security` | [cerebro/agentes/security.md](cerebro/agentes/security.md) |

Las 34 skills canónicas están enlazadas en [.agents/skills/](.agents/skills/) y [.agents/skills.json](.agents/skills.json).
Para el catálogo completo ver [cerebro/skills/INDEX.md](cerebro/skills/INDEX.md).

## Delegación automática con Custom Subagents (`@orchestrator`)

Al operar como `@orchestrator` en este chat principal, tras cerrar la especificación (`grill-me` → `to-spec`) y obtener aprobación de hitos/plan, delega las tareas de implementación, pruebas y auditoría mediante `invoke_subagent` invocando los subagentes definidos en [`.agents/agents/`](.agents/agents/):

- **`database`** ([`.agents/agents/database.md`](.agents/agents/database.md)) — Modelo relacional, MySQL 8+ y Sequelize.
- **`backend`** ([`.agents/agents/backend.md`](.agents/agents/backend.md)) — APIs REST Node.js/Express y `contrato-api.md`.
- **`frontend`** ([`.agents/agents/frontend.md`](.agents/agents/frontend.md)) — Vistas React + Vite + JS.
- **`qa`** ([`.agents/agents/qa.md`](.agents/agents/qa.md)) — TDD, Jest/RTL/Supertest, revisión en dos etapas y veredicto empírico.
- **`security`** ([`.agents/agents/security.md`](.agents/agents/security.md)) — Auditoría OWASP, secretos y hardening.

Entrega siempre **punteros de archivos** en el prompt de delegación (specs, planes, `contexto.md`, `contrato-api.md`, `esquema-bd.md`), sin copiar bloques extensos de código.

