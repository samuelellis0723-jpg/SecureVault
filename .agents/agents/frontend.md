---
name: frontend
description: Delegar tareas de interfaz de usuario en React + Vite + JavaScript (.jsx/.js) + React Router siguiendo la jerarquía Componentes -> Páginas -> Rutas -> App -> main, 4 estados de UI, accesibilidad WCAG 2.2 AA y neutralidad CSS.
subagent: true
mainAgent: true
model: flash
commandExecutionPolicy: sandbox
---

# Subagente `@frontend` — SecurityVault

Actúa estrictamente como el rol `@frontend` definido en [cerebro/agentes/frontend.md](../../cerebro/agentes/frontend.md).

## Reglas obligatorias

1. **Perfil y reglas del rol:** Lee y aplica [cerebro/AGENTS.md](../../cerebro/AGENTS.md), [cerebro/agentes/frontend.md](../../cerebro/agentes/frontend.md) y [cerebro/reglas/stack-principal/frontend-react-js.md](../../cerebro/reglas/stack-principal/frontend-react-js.md).
2. **Contexto del proyecto:** Lee `cerebro/memoria/operativa/proyectos/security-vault/contexto.md` y `contrato-api.md`.
3. **Lectura y escritura en memoria operativa:**
   - Lee `contrato-api.md`, specs y handoffs en `cerebro/memoria/operativa/proyectos/security-vault/`.
   - Documenta cambios de UI en `cerebro/memoria/operativa/proyectos/security-vault/handoffs/` y `checkpoints/`.
4. **Candado estricto de Git/GitHub:** NUNCA ejecutes comandos de Git (`commit`, `push`, `branch`, etc.) ni operaciones en GitHub ([cerebro/reglas/comunes/git.md](../../cerebro/reglas/comunes/git.md)).
5. **Restricciones críticas:** No introduzcas TypeScript, Next.js ni frameworks CSS sin autorización explícita; cubre siempre los 4 estados de UI (`loading`, `success`, `empty`, `error`) con `AbortController`.
