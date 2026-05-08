---
title: Project State
tags:
  - agent-memory/state
type: state
project: satoidc
status: active
updated: 2026-05-08
---

# Project State

SatOIDC is a Python project for an OpenID Connect provider with Bitcoin/Lightning LNURL-auth integration.

Important paths:

- `satoidc/pyproject.toml`: Poetry project configuration and taskipy commands.
- `satoidc/satoidc/__init__.py`: FastAPI app setup and NiceGUI integration.
- `satoidc/satoidc/routes/`: browser and API routes.
- `satoidc/satoidc/auth/`: OAuth2, LNURL, security, and scopes.
- `satoidc/satoidc/fastapi_oauth2/`: local FastAPI integration layer for Authlib.
- `satoidc/satoidc/schemas/`: centralized Pydantic schemas for LNURL callback, login form, and registration form.
- `satoidc/satoidc/models/`: SQLAlchemy models and database setup.
- `satoidc/migrations/`: Alembic migrations.
- `satoidc/DockerFile`, `satoidc/entrypoint.sh`, `compose.yaml`, `.dockerignore`, `.env.example`: production-like Docker Compose stack with PostgreSQL healthcheck, cached Poetry dependency install, non-root app runtime, migrations, setup wizard, and FastAPI startup.
- `examples/`: OIDC client examples.
- `specs/`: Spec-Driven Development workspace for feature specs, flows, contracts, and SDD decisions.
- `DESIGN.md`: SatOIDC product design system for premium NiceGUI/Quasar/Tailwind UI, including global theme strategy, shared primitives, screen patterns, accessibility, and visual verification.

The repository root is also the Obsidian vault root for project memory.

Documentation added after full project analysis:

- `docs/project-analysis.md`: broad repository, architecture, runtime, flows, validation, and risk analysis.
- `docs/architecture.md`: system architecture and sequence diagrams.
- `docs/known-issues.md`: prioritized technical debt.
- `specs/contracts/oidc.md`: draft OIDC contract.
- `specs/flows/authorization-code.md`, `specs/flows/login.md`, `specs/flows/lnurl-auth.md`: draft SDD flow docs.
- `specs/flows/registration.md`: password and LNURL registration flow after separating `/register` UI from `POST /register` behavior.
- `docs/changes-2026-05-08.md`: detailed change log for schema package, registration endpoint, tests, and coverage policy.

Current test structure:

- `poetry run task test` runs unit/integration tests with browser e2e tests deselected by default.
- `poetry run task test_e2e` runs Playwright browser smoke/responsive tests under `satoidc/tests/e2e/`.
- `satoidc/tests/test_time_sensitive.py` uses `freezegun` for time-dependent behavior such as authorization-code expiration, refresh-token active/revoked windows, and LNURL challenge expiration.
- As of 2026-05-08, `poetry run task test` passes with `81 passed, 10 deselected` and 100% measured line coverage.
- Coverage-related `pragma: no cover` annotations are intentionally limited to NiceGUI visual rendering helpers/pages, QR UI classes, the LNURL schema compatibility shim, and a defensive parse branch. Browser e2e smoke tests cover the visual page rendering surface.

Recent implementation state:

- `POST /register` now handles password registration, terms acceptance, validation, duplicate login/email checks, user creation, session login, and sanitized redirects.
- `/register` remains the NiceGUI page and posts a standard HTML form to `POST /register`.
- `auth/lnurl_schemas.py` is now compatibility-only; new imports should use `satoidc.schemas.lnurl`.
- `fastapi_oauth2/authorization_server.py` uses `json.load()` for metadata files.
- `page_security` now delegates to testable helpers for permission loading and page authorization; invalid session UUIDs redirect to `/login`, and protected page return values are preserved.

UI design support:

- `C:\Users\luss1\.codex\skills\nicegui-premium-design\`: reusable Codex skill for premium NiceGUI SaaS redesign work. Use it when modernizing SatOIDC screens or creating new NiceGUI UI patterns.
- NiceGUI UI behavior should be checked against `https://nicegui.io/` and `https://nicegui.io/documentation`; custom JavaScript or DOM/browser-storage workarounds require explicit user authorization.
