# Spec: Testcontainers Integration Tests

## Status

- Status: draft
- Owner: project maintainers
- Created: 2026-05-16
- Updated: 2026-05-16
- Related code:
  - `satoidc/pyproject.toml`
  - `satoidc/tests/`
  - `satoidc/migrations/`
  - `compose.yaml`
- Related specs:
  - `specs/features/quality-testing/spec.md`
  - `specs/contracts/database.md`
  - `specs/contracts/runtime-config.md`
  - `specs/flows/deployment.md`

## Intent

Use Testcontainers to verify SatOIDC against PostgreSQL and other
production-like services without requiring developers to maintain permanent
local test infrastructure.

## Context

SatOIDC supports SQLite for local/test/simple deployments and PostgreSQL for
production. The default tests currently use isolated SQLite databases.
`testcontainers` is already present in the development dependency group.

## Scope

In scope:

- PostgreSQL-backed migration and persistence tests.
- Async and sync database URL consistency checks.
- Authlib sync helper behavior against PostgreSQL.
- Email-server integration tests for verification and account recovery delivery.
- OpenBao integration tests for the Vault-compatible Transit signing backend.

Out of scope:

- Replacing fast SQLite tests.
- Running containers as part of the default test command.
- Managing long-lived local Docker Compose test stacks.

## Rules

- Container tests must be marked `integration` or `container`.
- Container tests run only through an explicit task command.
- Tests must create disposable containers and clean them up after the run.
- PostgreSQL tests must run Alembic migrations rather than relying only on
  `metadata.create_all`.
- Tests must verify both async route sessions and Authlib sync sessions point to
  the same physical database.
- Email verification/account recovery implementation must include a
  Testcontainers-backed disposable email server rather than relying only on
  console or mocked delivery.
- OpenBao/Vault-compatible signing implementation must include a
  Testcontainers-backed OpenBao service rather than relying only on a fake
  Transit adapter.
- Container logs and failures must not expose secrets beyond test-only
  credentials.

## Task Commands

- `poetry run task test_integration`: `pytest -m "integration or container"`
- `poetry run task test_all`: `pytest -m "not load and not slow"`

## Acceptance Criteria

- Given Docker is available, when the integration task runs, then PostgreSQL
  starts through Testcontainers and migrations apply successfully.
- Given `poetry run task test_integration` runs, then only container-backed
  integration tests are selected.
- Given the app is configured with PostgreSQL URLs, then async routes and
  Authlib sync helpers operate on the same database.
- Given database migrations are added, then integration tests catch
  PostgreSQL-specific incompatibilities.
- Given email verification or recovery sends a message, then a disposable email
  server started by Testcontainers captures the expected message and link.
- Given OpenBao-backed signing is configured, then OpenBao starts through
  Testcontainers and SatOIDC signs through the Vault-compatible Transit path.
- Given Docker is unavailable, then integration tests skip or fail with a clear
  environment message instead of failing obscurely.

## Implementation Notes

- Keep container fixtures separate from default SQLite fixtures to preserve
  local test speed.
- Prefer a small number of high-signal PostgreSQL tests over duplicating the
  entire SQLite suite.
- Use test-only credentials and random database names generated per test run.
- Prefer lightweight, purpose-built service containers for email capture and
  OpenBao. Avoid requiring long-lived Docker Compose services for these tests.
