# AGENTS.md

## Project Overview

- SatOIDC is a Python OpenID Connect provider that combines OAuth2/OIDC flows with Bitcoin/Lightning LNURL-auth.
- The runnable app lives in `satoidc/`; the FastAPI/NiceGUI application package is `satoidc/satoidc/`.
- OAuth/OIDC protocol integration is under `satoidc/satoidc/auth/`, `satoidc/satoidc/fastapi_oauth2/`, and `satoidc/satoidc/routes/oauth2.py`.
- Browser-facing NiceGUI routes live in `satoidc/satoidc/routes/`; examples live in `examples/`.
- Start project orientation from `docs/project-analysis.md`, `docs/architecture.md`, and `docs/known-issues.md` before doing broad analysis again.

## Build And Test Commands

- Install dependencies: `cd satoidc; poetry install`
- Apply migrations: `cd satoidc; poetry run alembic upgrade head`
- Run development server: `cd satoidc; poetry run task run`
- Run tests: `cd satoidc; poetry run task test`
- Run public client example: `cd satoidc; poetry run task start_public_client <client-id>`

## Conventions

- Use `specs/` for Spec-Driven Development. For behavior changes, create or update a spec before implementation when the change affects auth, OIDC/OAuth2 behavior, LNURL-auth, persistence, security, user flows, or public contracts.
- Follow the existing FastAPI plus NiceGUI routing style.
- Keep protocol behavior aligned with OpenID Connect, OAuth2, Authlib, and LNURL-auth semantics.
- Prefer existing helpers in `satoidc/satoidc/auth/`, `satoidc/satoidc/models/`, and `satoidc/satoidc/validators.py` before adding new abstractions.
- Keep route-level UI changes consistent with the existing NiceGUI component and class patterns.
- Add focused tests for protocol, auth, validation, and persistence changes; broaden tests when behavior crosses route/model boundaries.

## Safety And Boundaries

- Do not commit secrets, `.env` files, local databases, virtualenvs, coverage output, or NiceGUI local storage.
- Treat `satoidc/database.db` and `satoidc/satoidc.db` as local runtime data.
- Do not rewrite migrations or generated artifacts unless the task explicitly requires it.
- Before changing auth, token, redirect, client registration, or key material handling, inspect the surrounding tests and OIDC expectations.

## Agent Memory

- Use `agent-memory/` for durable project memory.
- Search memory before reading many source files.
- Record only stable decisions, validated commands, recurring pitfalls, and open questions.
- Key memory entry points are `agent-memory/index.md`, `agent-memory/architecture.md`, and `agent-memory/risks.md`.
