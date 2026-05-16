---
title: Project State
tags:
  - agent-memory/state
type: state
project: satoidc
status: active
updated: 2026-05-16
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
- Planned quality-testing commands are specified in `specs/features/quality-testing/` but are not implemented yet: `test_unit`, `test_property`, `test_api_security`, `test_integration`, `test_load`, and `test_all`.
- `satoidc/tests/test_time_sensitive.py` uses `freezegun` for time-dependent behavior such as authorization-code expiration, refresh-token active/revoked windows, and LNURL challenge expiration.
- As of 2026-05-15, `poetry run task test` passes with `113 passed, 17 deselected`.
- As of 2026-05-15, `poetry run task test_e2e` passes with `17 passed`.
- Coverage-related `pragma: no cover` annotations are intentionally limited to NiceGUI visual rendering helpers/pages, QR UI classes, the LNURL schema compatibility shim, and a defensive parse branch. Browser e2e smoke tests cover the visual page rendering surface.

Recent implementation state:

- `POST /register` now handles password registration, terms acceptance, validation, duplicate login/email checks, user creation, session login, and sanitized redirects.
- `/register` remains the NiceGUI page and posts a standard HTML form to `POST /register`.
- `auth/lnurl_schemas.py` is now compatibility-only; new imports should use `satoidc.schemas.lnurl`.
- `fastapi_oauth2/authorization_server.py` uses `json.load()` for metadata files.
- `page_security` now delegates to testable helpers for permission loading and page authorization; invalid session UUIDs redirect to `/login`, and protected page return values are preserved.
- OIDC signing keys are persisted in `oidc_signing_keys`, private JWKs are encrypted with a key derived from `OAUTH2_JWT_SECRET_KEY`, JWKS publishes only `active` and `validating` public keys, and ID Tokens include the active `kid`.
- `developer` is a first-class permission enum value. Developer access requests persist in `permission_requests`; profile can submit requests, admin dashboard can approve or deny them, and approval grants a `developer` permission.
- Authenticated Playwright e2e coverage now covers signed-in home/profile rendering, profile wallet-link QR dialog smoke behavior, developer dashboard empty/populated states, create-client validation/success, and admin approval of permission requests.
- Full OAuth authorization-code browser e2e coverage now exercises login, consent, redirect, token exchange, ID Token, refresh token issuance, and UserInfo for public PKCE and confidential `client_secret_post` clients.
- OAuth client management is integrated in the developer dashboard with edit, delete, disable/enable, identifier copy, and secret rotation actions.
- `docs/priority-execution-backlog.md` is now a temporary active queue for open work only. Completed backlog items are summarized in `docs/priority-execution-history.md`.
- Open work includes public route boundary hardening, OpenBao/Vault-compatible signing, SQLite/PostgreSQL matrix validation, service extraction, operational observability, token load checks, email verification/account recovery, and test-layer refactoring for the quality-testing specs.

UI design support:

- `C:\Users\luss1\.codex\skills\nicegui-premium-design\`: reusable Codex skill for premium NiceGUI SaaS redesign work. Use it when modernizing SatOIDC screens or creating new NiceGUI UI patterns.
- NiceGUI UI behavior should be checked against `https://nicegui.io/` and `https://nicegui.io/documentation`; custom JavaScript or DOM/browser-storage workarounds require explicit user authorization.
