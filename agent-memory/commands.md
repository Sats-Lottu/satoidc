---
title: Validated Commands
tags:
  - agent-memory/command
type: command
project: satoidc
status: active
updated: 2026-05-15
---

# Validated Commands

- `obsidian vault="satoidc" search query="agent-memory" limit=10`: returned `Vault not found` before this repository was initialized as the project vault.
- `obsidian vault="satoidc" vault`: validated after initialization; resolves to `C:\Users\luss1\Documents\GitHub\satoidc`.
- `obsidian vault="satoidc" read path="agent-memory/index.md"`: validated after initialization; reads the project memory index.
- `Get-ChildItem -Recurse specs`: validated the SDD folder structure after creating `specs/`.
- `cd satoidc; poetry run task test`: ran on 2026-05-06 after test coverage updates; passed with e2e tests deselected by default.
- `cd satoidc; poetry run task playwright_install`: ran on 2026-05-06 with network approval; installed Chromium for Playwright e2e tests.
- `cd satoidc; poetry run task test_e2e`: ran on 2026-05-06 with browser subprocess approval; passed browser e2e smoke/responsive tests.
- `cd satoidc; poetry run ruff check`: ran on 2026-05-06 after adding time-sensitive tests; passed.
- `cd satoidc; poetry run task test`: ran on 2026-05-06 after adding `freezegun` tests; passed with `33 passed, 10 deselected` and coverage at 58%.
- Markdown documentation link/orphan check with PowerShell: ran on 2026-05-06 after documentation index updates; no broken Markdown links and no unreferenced Markdown files outside root entry points.
- `cd satoidc; poetry run ruff check`: ran on 2026-05-06 after documentation/index cleanup; passed.
- `cd satoidc; poetry run task test`: ran on 2026-05-06 after documentation/index cleanup; passed with `33 passed, 10 deselected` and coverage at 58%.
- `cd satoidc; poetry run python -m compileall satoidc setup_wizard tests`: ran on 2026-05-06; passed.
- `obsidian vault="satoidc" search query="JWT" path="agent-memory" limit=10`: ran on 2026-05-06; found new memory files.
- `obsidian vault="satoidc" search query="Spec-Driven" path="specs" limit=10`: ran on 2026-05-06; found SDD docs.
- `cd satoidc; poetry run task run`: canonical development server command from `satoidc/pyproject.toml`; not run during vault initialization.
- `docker compose config`: ran on 2026-05-06 after dockerization updates; passed and resolved `SATOIDC_PORT` to `8000`.
- `docker compose build satoidc`: ran on 2026-05-06 with Docker access approval; passed.
- `docker compose up -d`: ran on 2026-05-06 with Docker access approval; Postgres became healthy, migrations ran, SatOIDC started, and `http://127.0.0.1:8000/` returned `200 OK`.
- `docker compose down`: ran on 2026-05-06 after validation; stopped the temporary stack while preserving volumes.
- `cd satoidc; poetry run ruff check`: ran on 2026-05-08 after schema, registration, and coverage changes; passed.
- `cd satoidc; poetry run task test`: ran on 2026-05-08 after adding focused coverage tests and `pragma: no cover` annotations for UI-only code; passed with `75 passed, 10 deselected` and 100% measured line coverage.
- `cd satoidc; poetry run task test_e2e`: ran on 2026-05-08 after coverage changes; passed with `10 passed`.
- `cd satoidc; poetry run task test`: ran on 2026-05-08 after adding `page_security` tests and refactoring; passed with `81 passed, 10 deselected` and 100% measured line coverage.
- `cd satoidc; poetry run ruff check satoidc tests`: ran on 2026-05-08 after SatOIDC light/dark UI harmonization using NiceGUI `ui.colors` plus Tailwind classes; passed.
- `cd satoidc; poetry run task test`: ran on 2026-05-08 after SatOIDC light/dark UI harmonization using NiceGUI `ui.colors` plus Tailwind classes; passed with `81 passed, 10 deselected` and 100% measured line coverage.
- `cd satoidc; poetry run task test_e2e`: ran on 2026-05-08 after SatOIDC light/dark UI harmonization using NiceGUI `ui.colors` plus Tailwind classes; passed with `10 passed`.
- `cd satoidc; poetry run ruff check satoidc tests`: ran on 2026-05-13 after implementing the UI backlog items for home/header/profile/create-client; passed.
- `cd satoidc; poetry run task test`: ran on 2026-05-13 after implementing the UI backlog items for home/header/profile/create-client; passed with `84 passed, 10 deselected`.
- `cd satoidc; poetry run task test_e2e`: ran on 2026-05-13 after implementing the UI backlog items for home/header/profile/create-client; passed with `10 passed`.
- `cd satoidc; poetry run pytest tests/test_oidc_key_rotation.py tests/test_oauth_metadata.py tests/test_oauth_grants.py`: ran on 2026-05-13 after OIDC key rotation implementation; passed with `15 passed`.
- `cd satoidc; poetry run ruff check`: ran on 2026-05-13 after OIDC key rotation implementation; passed.
- `cd satoidc; poetry run task test`: ran on 2026-05-13 after OIDC key rotation implementation; passed with `97 passed, 10 deselected`.
- `cd satoidc; poetry run alembic upgrade head`: ran on 2026-05-13 after adding `oidc_signing_keys` migration; applied `6c2f4c9d1a7e`.
- `cd satoidc; poetry run ruff check`: ran on 2026-05-15 after completing priority backlog e2e and protocol adapter fixes; passed.
- `cd satoidc; poetry run task test`: ran on 2026-05-15 after completing priority backlog; passed with `113 passed, 17 deselected`.
- `cd satoidc; poetry run task test_e2e`: ran on 2026-05-15 after completing priority backlog; passed with `17 passed`.
- `rg -n "Ã|Â|â|pÃ|nÃ|LÃ|Ãº|Ã£|Ã§|Ã©|Ã³" README.md examples satoidc\satoidc\docs docs agent-memory specs`: ran on 2026-05-15; found no mojibake patterns.
