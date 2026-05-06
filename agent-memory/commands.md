---
title: Validated Commands
tags:
  - agent-memory/command
type: command
project: satoidc
status: active
updated: 2026-05-06
---

# Validated Commands

- `obsidian vault="satoidc" search query="agent-memory" limit=10`: returned `Vault not found` before this repository was initialized as the project vault.
- `obsidian vault="satoidc" vault`: validated after initialization; resolves to `C:\Users\luss1\Documents\GitHub\satoidc`.
- `obsidian vault="satoidc" read path="agent-memory/index.md"`: validated after initialization; reads the project memory index.
- `Get-ChildItem -Recurse specs`: validated the SDD folder structure after creating `specs/`.
- `cd satoidc; poetry run task test`: ran on 2026-05-06; failed because pytest collected zero tests and coverage collected no data.
- `cd satoidc; poetry run python -m compileall satoidc setup_wizard tests`: ran on 2026-05-06; passed.
- `obsidian vault="satoidc" search query="JWT" path="agent-memory" limit=10`: ran on 2026-05-06; found new memory files.
- `obsidian vault="satoidc" search query="Spec-Driven" path="specs" limit=10`: ran on 2026-05-06; found SDD docs.
- `cd satoidc; poetry run task run`: canonical development server command from `satoidc/pyproject.toml`; not run during vault initialization.
- `docker compose config`: ran on 2026-05-06 after dockerization updates; passed and resolved `SATOIDC_PORT` to `8000`.
- `docker compose build satoidc`: ran on 2026-05-06 with Docker access approval; passed.
- `docker compose up -d`: ran on 2026-05-06 with Docker access approval; Postgres became healthy, migrations ran, SatOIDC started, and `http://127.0.0.1:8000/` returned `200 OK`.
- `docker compose down`: ran on 2026-05-06 after validation; stopped the temporary stack while preserving volumes.
