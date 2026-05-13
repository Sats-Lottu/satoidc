# Deployment Flow

Status: draft
Area: Operations
Last Updated: 2026-05-13

## Intent

Describe the current container and local deployment behavior.

## Local Development

Expected commands:

```powershell
cd satoidc
poetry install
poetry run alembic upgrade head
poetry run task run
```

The app uses SQLite defaults unless `.env` overrides database URLs.

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

1. Runs Alembic migrations.
2. Runs setup wizard if a root user is missing.
3. Starts FastAPI on `0.0.0.0:8000`.

## Compose Stack

`compose.yaml` defines:

- `database`: PostgreSQL 16 with a persistent `pgdata` volume.
- `satoidc`: application service built from `satoidc/DockerFile`.

PostgreSQL defaults:

- user: `app_user`
- database: `app_db`
- password: `app_password`

SatOIDC environment:

- `DATABASE_URL`: PostgreSQL async URL.
- `SYNC_DATABASE_URL`: PostgreSQL sync URL.
- `OAUTH2_JWT_ISS`: defaults to `http://localhost:8000`.
- `SESSION_MIDDLEWARE_SECRET_KEY`: defaults to a development placeholder.

Ports:

- Host `${SATOIDC_PORT:-8000}` maps to container `8000`.

Startup dependency:

- SatOIDC waits for database health before running.

## Production Gaps

- Session secret default is unsafe for production.
- Database password defaults are unsafe for production.
- Session cookies are not currently `https_only`.
- OIDC signing keys are process-local and not persisted.
- No external secret manager integration exists.

## Acceptance Criteria

- Given Compose starts with defaults, then PostgreSQL becomes healthy before
  SatOIDC runs migrations.
- Given no root permission exists, then the setup wizard starts before the main
  app.
- Given root setup completes, then the main FastAPI app starts on port 8000.
- Given the app starts, then the healthcheck can fetch `/`.
