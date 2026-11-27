# Reglas Operativas — Integración cerebro-agentes en SecurityVault

Este proyecto (`SecurityVault`) está gobernado por el sistema operativo agéntico **`cerebro-agentes`** ubicado en `cerebro/` (`/home/panterita/Documents/ReposDeSkills/cerebro-agentes`).

## 1. Principios innegociables

1. **Candado estricto de Git/GitHub:** NUNCA ejecutar comandos git (`commit`, `push`, `branch`, etc.) ni operaciones GitHub salvo solicitud expresa y literal del usuario ([cerebro/reglas/comunes/git.md](cerebro/reglas/comunes/git.md)).
2. **Evidencia antes de afirmar éxito:** Todo reporte de verificación debe incluir evidencia empírica real y emitir veredicto `PASS`, `FAIL`, `BLOCKED` o `NOT TESTED` ([cerebro/reglas/comunes/testing.md](cerebro/reglas/comunes/testing.md)).
3. **Stack principal por defecto:**
   - **Frontend:** React + Vite + JavaScript (`.jsx`/`.js`) + React Router (`Componentes → Páginas → Rutas → App → main`), neutralidad CSS.
   - **Backend:** Node.js + Express REST en capas limpias.
   - **Base de datos:** MySQL 8+ + Sequelize / `mysql2` parametrizado. *(Supabase/PostgreSQL solo si `cerebro/memoria/operativa/proyectos/security-vault/contexto.md` declara `modulos_activos: [supabase]`)*.
   - **Pruebas:** Jest + React Testing Library + Supertest.
4. **Divulgación progresiva:** Tareas triviales (1 especialista directo), tareas estándar (especialista + QA), tareas complejas (orquestación completa con `@orchestrator`).

## 2. Punteros de memoria del proyecto

- Contexto: [contexto.md](cerebro/memoria/operativa/proyectos/security-vault/contexto.md)
- Arquitectura: [arquitectura.md](cerebro/memoria/operativa/proyectos/security-vault/arquitectura.md)
- Contrato API: [contrato-api.md](cerebro/memoria/operativa/proyectos/security-vault/contrato-api.md)
- Esquema BD: [esquema-bd.md](cerebro/memoria/operativa/proyectos/security-vault/esquema-bd.md)
