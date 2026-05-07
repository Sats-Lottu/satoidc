---
title: Decisions
tags:
  - agent-memory/decision
type: decision
project: satoidc
status: active
updated: 2026-05-06
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
