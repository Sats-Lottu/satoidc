---
title: Decisions
tags:
  - agent-memory/decision
type: decision
project: satoidc
status: active
updated: 2026-05-13
---

# Decisions

- 2026-05-06: Use `satoidc` as the Obsidian vault for this project. If the vault is not registered in Obsidian, initialize the repository itself as the vault root.
- 2026-05-06: Keep project memory in root `agent-memory/` so agents can discover it without scanning implementation directories.
- 2026-05-06: Keep `AGENTS.md` as the canonical agent instruction file. Add tool-specific adapters only if a tool requires them later.
- 2026-05-06: Adopt a `specs/` folder for Spec-Driven Development, targeting a spec-anchored workflow where specs and implementation evolve together.
- 2026-05-06: Add `DESIGN.md` because SatOIDC has a browser-facing NiceGUI interface and needs stable UI conventions.
- 2026-05-06: Prefer `python:3.11-slim` over Alpine for the application image to reduce native dependency friction for packages such as `psycopg`, `cryptography`, NiceGUI, and Uvicorn.
- 2026-05-06: Compose should expose SatOIDC on `${SATOIDC_PORT:-8000}` and wait for PostgreSQL health before running migrations.
- 2026-05-06: Track OIDC signing key lifecycle as a dedicated feature spec at `specs/features/oidc-key-rotation/`; prefer Vault Transit for the final cryptographic backend, with encrypted private-key storage acceptable only as an MVP fallback.
- 2026-05-07: Rework `DESIGN.md` as the canonical SatOIDC product design system for premium NiceGUI/Quasar/Tailwind SaaS UI. Future interface changes should update global NiceGUI defaults and shared primitives before local route styling.
- 2026-05-07: Add reusable Codex skill `nicegui-premium-design` at `C:\Users\luss1\.codex\skills\nicegui-premium-design\` for NiceGUI redesign work, including global theme workflow, shared primitive patterns, Tailwind recipes, and verification checklist.
- 2026-05-08: NiceGUI UI behavior must use the official NiceGUI documentation first and prefer native NiceGUI APIs. Custom JavaScript, direct DOM manipulation, and manual browser storage workarounds require explicit user authorization.
- 2026-05-08: Keep Pydantic request/form schemas in `satoidc/satoidc/schemas/`. Route modules should import schemas from that package instead of defining them inline; legacy schema import paths may stay as compatibility shims.
- 2026-05-08: Keep browser-facing NiceGUI pages focused on rendering and move persistence/session behavior into FastAPI endpoints when a route has form submission behavior, as done for `POST /register`.
- 2026-05-08: Use `pragma: no cover` only for UI rendering glue, compatibility shims, or defensive branches that are not useful unit-test targets; maintain behavior coverage through focused unit/integration tests and visual coverage through Playwright e2e smoke tests.
- 2026-05-08: Treat `page_security` as authorization logic rather than UI glue. Keep it covered by focused tests and delegate database permission loading plus request authorization to testable helpers.
- 2026-05-08: SatOIDC theme changes should prefer NiceGUI `ui.colors(...)`, `default_props`, `default_classes`, and shared Tailwind class helpers. Do not use broad CSS injection through `ui.add_head_html` for normal visual theming.
- 2026-05-08: Use the shared `responsive_grid()` helper for route grids instead of `ui.grid(columns=...)` when mobile collapse is required. The helper emits Tailwind grid classes on a plain element.
- 2026-05-13: Keep global header utilities on the right side: navigation first, then theme toggle, then account menu. Signed-in home actions should use the account menu and profile/dashboard/logout actions instead of public login/register CTAs.
- 2026-05-13: Client registration must validate metadata before persistence and show generated credentials once after creation instead of redirecting immediately.
- 2026-05-13: LNURL callback attempts should consume their challenge even when signature validation fails. This is a replay-defense behavior; the implementation uses the `consumed` field to avoid implying successful signature verification.
