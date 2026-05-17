# Database Support Matrix

Updated: 2026-05-17

SatOIDC supports SQLite and PostgreSQL through paired async and sync SQLAlchemy
URLs. The async URL is used by FastAPI route dependencies, while the sync URL is
used by Authlib SQLAlchemy helpers.

| Database | Async URL | Sync URL | Intended Use | Verification |
| --- | --- | --- | --- | --- |
| SQLite file | `sqlite+aiosqlite:///satoidc.db` | `sqlite:///satoidc.db` | Local development, tests, demos, small single-node deployments | Default `poetry run task test` suite and migration command |
| SQLite memory | `sqlite+aiosqlite:///:memory:` | `sqlite:///:memory:` | Focused tests only | Runtime URL-pair tests |
| PostgreSQL | `postgresql+psycopg://...` | `postgresql+psycopg://...` | Production and production-like integration tests | `poetry run task test_integration` with Docker/Testcontainers |

## Rules

- `DATABASE_URL` and `SYNC_DATABASE_URL` must target the same backend and
  database name.
- SQLite async URLs must be paired with SQLite sync URLs.
- PostgreSQL async and sync URLs must both target the same PostgreSQL database.
- Runtime settings reject mixed backends and mismatched database names before
  engines are created.
- PostgreSQL migration compatibility is covered by a Testcontainers-backed
  integration test that applies Alembic migrations to PostgreSQL 16 and verifies
  both sync and async access to the migrated schema.

## Commands

```bash
cd satoidc
poetry run task test
poetry run task test_integration
```

`test_integration` requires Docker. When Docker is unavailable, container-backed
tests skip with an explicit environment message.
