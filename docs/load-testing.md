# Load Testing

This runbook defines the current bounded Locust smoke for SatOIDC. Load results
are local evidence only unless the target environment, database, request count,
failure rate, and latency percentiles are recorded with the run.

## Scope

The default load task exercises public metadata and login/register pages:

```bash
cd satoidc
poetry run task test_load
```

The task is intentionally short and local. It does not start the application
server; run SatOIDC separately and pass a different host with Locust arguments
when needed.

## Optional Token Lifecycle Seed

Token endpoint and UserInfo load are enabled only when explicit seed values are
provided. Seed a disposable OAuth client and one or more active refresh tokens
through a real authorization-code flow before the run.

Required for `/oauth/token` refresh-grant load:

```bash
SATOIDC_LOAD_CLIENT_ID=<client-id>
SATOIDC_LOAD_CLIENT_SECRET=<client-secret-for-confidential-clients>
SATOIDC_LOAD_REFRESH_TOKENS=<refresh-token-1>,<refresh-token-2>
```

Optional for `/oauth/userinfo` load before the first refresh:

```bash
SATOIDC_LOAD_ACCESS_TOKENS=<access-token-1>,<access-token-2>
```

Use one refresh token per concurrent token lifecycle user. The Locust scenario
keeps refresh-token rotation local to each simulated user, so reusing the same
refresh token across users will produce expected `invalid_grant` failures.

Do not store these environment values in `.env` files committed to the
repository. Do not paste tokens or client secrets into published reports.

## Recommended Baseline Command

Use PostgreSQL for any result that will inform deployment sizing:

```bash
cd satoidc
poetry run task test_load
```

For a token lifecycle smoke, use a small number of users first:

```bash
cd satoidc
poetry run locust -f tests/load/locustfile.py \
  --headless \
  --users 3 \
  --spawn-rate 1 \
  --run-time 1m \
  --host http://127.0.0.1:8000
```

## Result Template

Record load results under `docs/load-results/` using this shape:

```markdown
# Load Result: YYYY-MM-DD `/oauth/token`

- SatOIDC commit:
- Database: PostgreSQL or SQLite, version, host shape
- Host:
- Users:
- Spawn rate:
- Run time:
- Request count:
- Failure rate:
- p50 latency:
- p95 latency:
- p99 latency:
- CPU/RAM notes:
- Known limitations:
```

## Conservative Interpretation

- A passing local smoke proves only that the configured endpoints responded
  under the small bounded scenario.
- Do not publish SQLite results as production guidance.
- Treat any non-zero token endpoint failure rate as a blocker until failures
  are classified as bad seed data, expected refresh-token reuse, or a product
  bug.
