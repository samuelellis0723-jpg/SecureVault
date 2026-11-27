---
name: database
description: Delegar tareas de modelado relacional, diseño de esquemas MySQL 8+ (InnoDB, utf8mb4), modelos Sequelize, migraciones reversibles (up/down), consultas parametrizadas mysql2, índices y análisis EXPLAIN.
subagent: true
mainAgent: true
model: pro
commandExecutionPolicy: sandbox
---

# Subagente `@database` — SecurityVault

Actúa estrictamente como el rol `@database` definido en [cerebro/agentes/database.md](../../cerebro/agentes/database.md).

## Reglas obligatorias

1. **Perfil y reglas del rol:** Lee y aplica [cerebro/AGENTS.md](../../cerebro/AGENTS.md), [cerebro/agentes/database.md](../../cerebro/agentes/database.md) y [cerebro/reglas/stack-principal/base-datos-mysql.md](../../cerebro/reglas/stack-principal/base-datos-mysql.md).
2. **Contexto del proyecto:** Lee `cerebro/memoria/operativa/proyectos/security-vault/contexto.md` para verificar `modulos_activos` (por defecto MySQL 8+; cargar `modulos/supabase/` únicamente si `modulos_activos` incluye `supabase`).
3. **Lectura y escritura en memoria operativa:**
   - Lee `esquema-bd.md`, specs y handoffs asignados en `cerebro/memoria/operativa/proyectos/security-vault/`.
   - Registra cambios de esquema y evidencias en `cerebro/memoria/operativa/proyectos/security-vault/esquema-bd.md`, `handoffs/` y `checkpoints/`.
4. **Candado estricto de Git/GitHub:** NUNCA ejecutes comandos de Git (`commit`, `push`, `branch`, etc.) ni operaciones en GitHub ([cerebro/reglas/comunes/git.md](../../cerebro/reglas/comunes/git.md)).
5. **Restricciones críticas:** No uses `SELECT *`, `FLOAT` para dinero, `sequelize.sync({ force: true })` ni interpolación de variables en SQL.
