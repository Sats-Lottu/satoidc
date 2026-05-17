# Application Setup Bootstrap

## Status

- Status: implemented
- Owner: TBD
- Created: 2026-05-16
- Updated: 2026-05-17
- Related code:
  - `satoidc/entrypoint.sh`
  - `satoidc/setup_wizard/`
  - `satoidc/satoidc/settings.py`
  - `compose.yaml`
- Related specs:
  - `specs/flows/setup-wizard.md`
  - `specs/flows/deployment.md`
  - `specs/contracts/runtime-config.md`
  - `specs/features/oidc-key-rotation/spec.md`

## Intent

Refactor application setup so a fresh deployment can create or collect every
required runtime value before the main SatOIDC application starts.

The setup path must cover secrets, token/signing configuration, root-user
bootstrap, database readiness, and deployment safety checks instead of relying
on committed placeholders or incomplete environment variables.

## Context

The current container entrypoint runs migrations, starts the setup wizard only
for root-user creation, then starts FastAPI. Runtime settings already reject
placeholder secrets in production, but there is no unified setup step that can
detect missing values and generate safe defaults where appropriate.

For Coolify and VPS deployments, environment variables should remain managed by
the platform. The setup flow must therefore distinguish between values that can
be generated and persisted by SatOIDC and values that must be configured in the
deployment platform.

## Scope

In scope:

- Detect missing or placeholder runtime values during startup.
- Generate cryptographically strong secrets where SatOIDC can safely persist
  them.
- Guide operators to configure deployment-managed values in Coolify or the
  process environment.
- Keep root-user setup in the same bootstrap experience.
- Make the setup flow idempotent so reruns do not rotate secrets or tokens
  unexpectedly.
- Document which values are generated, operator-provided, or platform-managed.

Out of scope:

- Secret-manager integration such as OpenBao Transit.
- Full external signing backend implementation.
- Automatic mutation of Coolify environment variables through its API.
- Replacing PostgreSQL backup, restore, or migration runbooks.

## Rules

- Production startup must never proceed with placeholder secrets.
- Automatically generated secrets must use a cryptographically secure random
  source.
- Generated secrets must not be printed to normal logs after creation.
- Setup must not overwrite an existing non-placeholder secret unless an explicit
  rotation path is invoked.
- OIDC issuer and public domain values must be operator-provided because they
  depend on the public deployment URL.
- Database URLs must be validated for async/sync consistency before the app
  starts.
- Root-user bootstrap must remain blocked until a root permission exists.
- In Coolify deployments, runtime variables remain managed by Coolify.

## Flows

### Fresh Production Deployment

1. Entrypoint runs configuration and database connectivity checks.
2. Setup validates required runtime configuration.
3. Setup identifies missing or placeholder secrets.
4. Setup generates values that SatOIDC is allowed to own when
   `SETUP_GENERATED_SECRETS_PATH` points to an absolute persistence file.
5. Setup reports operator-required values that must be configured externally.
6. Entrypoint runs migrations.
7. Setup starts or skips root-user creation depending on existing permissions.
8. Setup validates root permission and OIDC signing-key readiness.
9. Main FastAPI app starts only after setup is complete.

### Existing Deployment Restart

1. Entrypoint runs setup validation.
2. Setup finds existing valid values and existing root permission.
3. Setup exits without rotating secrets or starting the root UI.
4. Main FastAPI app starts normally.

### Missing Operator-Managed Value

- Given production mode and a missing `OAUTH2_JWT_ISS`, when setup runs, then
  startup stops with an actionable message explaining that the public issuer URL
  must be configured in the deployment platform.

### Missing Generated Secret

- Given production mode and a missing internal application secret, when setup
  runs in an approved generation mode, then setup creates a strong secret,
  persists it in the configured setup storage, and does not print it in logs.

## Contracts

- Runtime configuration:
  - `APP_ENV`
  - `DOMAIN`
  - `DATABASE_URL`
  - `SYNC_DATABASE_URL`
  - `OAUTH2_JWT_ISS`
  - `OAUTH2_JWT_SECRET_KEY`
  - `SESSION_MIDDLEWARE_SECRET_KEY`
  - `SESSION_COOKIE_HTTPS_ONLY`
  - `SETUP_GENERATED_SECRETS_PATH`
- Bootstrap state:
  - root user and root permission existence
  - OIDC signing-key availability
  - generated secret persistence location
- Startup behavior:
  - fail closed when required production values are missing
  - skip setup when all requirements are satisfied

## Acceptance Criteria

- Given a fresh production deployment with placeholder secrets, when setup
  runs, then the app does not start until secrets are generated or configured.
- Given a fresh deployment with no root permission, when setup runs, then root
  creation is available before the main app starts.
- Given an existing deployment with valid secrets and a root permission, when
  setup runs, then setup exits without changing secrets.
- Given missing public issuer configuration, when setup runs, then startup fails
  with an actionable operator message.
- Given SQLite local development defaults, when setup runs outside production,
  then local development remains simple and does not require external secret
  setup.
- Given Coolify manages runtime variables, when setup reports missing
  operator-managed values, then the message names the exact Coolify variables
  to set.

## Test Plan

- Unit:
  - configuration classification for generated, operator-managed, and optional
    values
  - idempotent secret generation behavior
  - production fail-closed validation messages
- Integration:
  - entrypoint/setup sequencing with missing and complete configuration
  - database URL consistency validation
  - root-permission bootstrap compatibility
- UI/manual:
  - setup wizard messages for missing production configuration
  - successful root-user creation after configuration is complete
- Security/regression:
  - generated secret entropy and non-placeholder checks
  - no secret leakage in normal logs
  - no unintended secret rotation on restart

## Implementation Notes

- Prefer extending `setup_wizard` into an application bootstrap module rather
  than adding disconnected startup scripts.
- Keep platform-owned values in Coolify or environment variables; do not make
  SatOIDC mutate Coolify settings automatically in the first implementation.
- Consider a small setup-state abstraction if generated values need durable
  persistence outside the existing database.
- Sequence this before broader production hardening so deployment behavior is
  predictable.

## Traceability

- Code:
  - `satoidc/setup_wizard/bootstrap.py`
  - `satoidc/entrypoint.sh`
- Tests:
  - `satoidc/tests/test_bootstrap.py`
  - `satoidc/tests/test_settings.py`
  - `satoidc/tests/test_database.py`
- Docs:
  - `specs/flows/setup-wizard.md`
  - `docs/deployment/vps.md`
- Decisions: TBD
