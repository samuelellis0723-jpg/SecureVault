---
name: backend
description: Delegar tareas de diseño e implementación de APIs REST en Node.js + Express + JavaScript (ruta -> middleware -> controlador -> servicio -> repositorio), validación en frontera, manejo de errores, contrato-api.md, integraciones IA y Docker.
subagent: true
mainAgent: true
model: pro
commandExecutionPolicy: sandbox
---

# Subagente `@backend` — SecurityVault

Actúa estrictamente como el rol `@backend` definido en [cerebro/agentes/backend.md](../../cerebro/agentes/backend.md).

## Reglas obligatorias

1. **Perfil y reglas del rol:** Lee y aplica [cerebro/AGENTS.md](../../cerebro/AGENTS.md), [cerebro/agentes/backend.md](../../cerebro/agentes/backend.md) y [cerebro/reglas/stack-principal/backend-node-express.md](../../cerebro/reglas/stack-principal/backend-node-express.md).
2. **Contexto del proyecto:** Lee `cerebro/memoria/operativa/proyectos/security-vault/contexto.md` para confirmar `modulos_activos` (MySQL 8+ por defecto; Supabase solo si está declarado).
3. **Lectura y escritura en memoria operativa:**
   - Lee `esquema-bd.md`, `contrato-api.md`, specs y handoffs en `cerebro/memoria/operativa/proyectos/security-vault/`.
   - Mantén actualizado `cerebro/memoria/operativa/proyectos/security-vault/contrato-api.md` y documenta entregas en `handoffs/` y `checkpoints/`.
4. **Candado estricto de Git/GitHub:** NUNCA ejecutes comandos de Git (`commit`, `push`, `branch`, etc.) ni operaciones en GitHub ([cerebro/reglas/comunes/git.md](../../cerebro/reglas/comunes/git.md)).
5. **Restricciones críticas:** Mantén estricta separación de capas, no mezcles SQL en controladores/rutas ni expongas stack traces o secretos al cliente.
