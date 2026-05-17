# Deployment Flow

Status: draft
Area: Operations
Last Updated: 2026-05-17

## Intent

Describe the current container and local deployment behavior.

## CI/CD

The repository uses GitHub Actions for CI/CD:

- CI is defined in `.github/workflows/ci.yaml`.
- CI runs on `push` and `pull_request`.
- CI installs Python 3.11 and Poetry, installs dependencies from
  `satoidc/poetry.lock`, runs Ruff, runs the default non-e2e test suite, and
  builds the Docker Compose application image.
- CD is defined in `.github/workflows/deploy-coolify.yaml`.
- CD runs after CI succeeds on `main`, or manually through `workflow_dispatch`.
- CD calls the configured Coolify deploy webhook using GitHub Secrets.

Production environment variables remain in Coolify and must not be committed.

## Local Development

Expected commands:

```powershell
cd satoidc
poetry install
poetry run alembic upgrade head
poetry run task run
```

The app uses SQLite defaults unless `.env` overrides database URLs. SQLite must
remain supported for local development, tests, demos, and simple single-node
deployments.

## Docker Image

`satoidc/DockerFile`:

- Uses `python:3.11-slim`.
- Installs Poetry 2.x.
- Installs only main dependencies.
- Copies the `satoidc/` project into `/app`.
- Creates and runs as `appuser`.
- Exposes port 8000.
- Defines a healthcheck that fetches `http://127.0.0.1:8000/`.

## Entrypoint

`satoidc/entrypoint.sh`:

1. Validates bootstrap configuration and database connectivity.
2. Sources generated secrets from `SETUP_GENERATED_SECRETS_PATH` when the
   bootstrap created that file.
3. Runs Alembic migrations.
4. Runs setup wizard if a root user is missing.
5. Validates database-backed root permission and OIDC signing-key readiness.
6. Starts FastAPI on `0.0.0.0:8000`.

## Compose Stack

`compose.yaml` defines:

- `database`: PostgreSQL 16 with a persistent `pgdata` volume.
- `satoidc`: application service built from `satoidc/DockerFile`.

PostgreSQL defaults:

- user: `app_user`
- database: `app_db`
- password: `app_password`

PostgreSQL is the recommended production database target. SQLite support is
intentional, but PostgreSQL should be used when deployments need stronger
concurrency, operational backups, and multi-user production behavior.

SatOIDC environment:

- `APP_ENV`: defaults to `development`.
- `DOMAIN`: optional public domain metadata.
- `DATABASE_URL`: PostgreSQL async URL.
- `SYNC_DATABASE_URL`: PostgreSQL sync URL.
- `OAUTH2_JWT_ISS`: defaults to `http://localhost:8000`.
- `OAUTH2_JWT_SECRET_KEY`: defaults to a development placeholder.
- `OAUTH2_TOKEN_EXPIRES_IN`: defaults to `300`.
- `SESSION_MIDDLEWARE_SECRET_KEY`: defaults to a development placeholder.
- `SESSION_COOKIE_HTTPS_ONLY`: defaults to `false`.
- `SETUP_GENERATED_SECRETS_PATH`: optional absolute shell env file path used
  by bootstrap to persist generated-owned secrets before app startup.

Ports:

- Host `${SATOIDC_PORT:-8000}` maps to container `8000`.

Startup dependency:

- SatOIDC waits for database health before running.

## Production Gaps

- Database password defaults are unsafe for production.
- Production mode requires HTTPS-only session cookies.
- OIDC signing keys are persisted internally, but hardened production should
  prefer OpenBao Transit or another external signing backend.
- No external secret manager integration is implemented yet.

## OpenBao Deployment Position

SatOIDC must be deployable without OpenBao because it implements the OIDC key
lifecycle internally with encrypted database-backed private JWK storage.

For production hardening, SatOIDC should support OpenBao through a
Vault-compatible Transit backend:

- OpenBao is optional for local development and simple deployments.
- OpenBao is recommended when private signing keys should not be stored by the
  SatOIDC database at all.
- The internal mode carries a material risk: compromise of both the database and
  the runtime encryption secret can compromise OIDC signing and allow forged
  tokens.
- Production runbooks should explicitly state whether a deployment is using
  internal signing or OpenBao-backed signing.

## Acceptance Criteria

- Given Compose starts with defaults, then PostgreSQL becomes healthy before
  SatOIDC runs migrations.
- Given no root permission exists, then the setup wizard starts before the main
  app.
- Given root setup completes, then the main FastAPI app starts on port 8000.
- Given the app starts, then the healthcheck can fetch `/`.
- Given SQLite defaults are used, then local development can run without
  PostgreSQL.
- Given production Compose starts, then PostgreSQL is used for persistence.
- Given production Compose starts with `APP_ENV=production`, then placeholder
  secrets and insecure session cookies are rejected by application settings.
- Given production Compose starts with missing/local issuer configuration or
  mismatched async/sync database URLs, then bootstrap validation fails before
  migrations run.
- Given CI runs, then lint, non-e2e tests, and Docker image build are executed.
- Given CI succeeds on `main`, then CD can trigger the configured Coolify
  deployment webhook.
- Given OpenBao is not configured, then the app can still run with internal
  signing and the deployment docs expose the associated risk.
