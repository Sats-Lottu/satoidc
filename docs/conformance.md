# OIDC Basic OP Conformance Environment

This document describes how to prepare a disposable SatOIDC instance for
OpenID Foundation Basic OP conformance testing. Follow it from start to
finish before running the conformance suite. Do not use production secrets,
real user accounts, or production databases during conformance testing.

Related spec: [OIDC Conformance Evidence](../specs/features/oidc-conformance/spec.md)

---

## Targeted Profile

SatOIDC targets the **OpenID Connect Core 1.0 Basic OP** profile:

| Dimension                    | Value                                    |
| ---------------------------- | ---------------------------------------- |
| Response types               | `code`                                   |
| Grant types                  | `authorization_code`, `refresh_token`    |
| Subject types                | `public`                                 |
| ID token signing algorithms  | `RS256`                                  |
| PKCE challenge methods       | `S256`                                   |
| Scopes                       | `openid`, `email`, `profile`             |
| Token endpoint auth methods  | `none`, `client_secret_post`, `client_secret_basic` |

Flows **not** advertised and **not** in scope for this conformance target:

- Implicit flow
- Hybrid flow
- Dynamic client registration

---

## Prerequisites

- Python 3.11+ and [Poetry](https://python-poetry.org/) installed.
- The SatOIDC repository cloned locally.
- Dependencies installed: `cd satoidc && poetry install`.
- A working Alembic head migration: `poetry run alembic upgrade head`.
- **No production `.env` file loaded** during this procedure.

---

## Seed Data

The conformance instance requires a known root user and a registered OIDC
client so the conformance suite can perform interactive and non-interactive
flows without a live GUI registration step.

### Conformance Test User

| Field    | Value                          |
| -------- | ------------------------------ |
| Login    | `conformtest`                  |
| Email    | `conformtest@satoidc.local`    |
| Password | `ConformPass1!`                |
| Role     | Root (bootstrapped from env)   |

The bootstrap command creates this user if the `SATOIDC_ADMIN_*` variables are
set (see [Environment Variables](#environment-variables) below). No manual UI
step is required for the root user.

### Conformance OIDC Client

Register this client after the first startup using the SatOIDC developer
dashboard (`http://localhost:8000/create_client`) or programmatically via the
test fixtures. Use the following values:

| Field                     | Confidential client value              | Public (PKCE) client value   |
| ------------------------- | -------------------------------------- | ---------------------------- |
| Client name               | `oidf-conformance-confidential`        | `oidf-conformance-public`    |
| Redirect URI              | `https://www.certification.openid.net/test/a/satoidc/callback` | `https://www.certification.openid.net/test/a/satoidc/callback` |
| Allowed scopes            | `openid email profile`                 | `openid email profile`       |
| Token endpoint auth method| `client_secret_post`                   | `none`                       |
| Grant types               | `authorization_code`, `refresh_token`  | `authorization_code`, `refresh_token` |
| PKCE required             | optional                               | required (S256)              |

> **Note**: The redirect URI above is the OpenID Foundation hosted suite
> callback. For a locally self-hosted conformance runner, replace it with the
> callback URL of your conformance suite host (e.g.
> `http://localhost:8443/test/a/satoidc/callback`).

---

## Environment Variables

The table below lists every variable used by the conformance instance. Use
**disposable values** — never copy production secrets here.

| Variable                          | Purpose                              | Conformance example value                         |
| --------------------------------- | ------------------------------------ | ------------------------------------------------- |
| `DATABASE_URL`                    | Async database URL                   | `sqlite+aiosqlite:///conformance.db`              |
| `SYNC_DATABASE_URL`               | Sync database URL (same DB)          | `sqlite:///conformance.db`                        |
| `OAUTH2_JWT_ISS`                  | Issuer identifier (must match external URL seen by suite) | `http://localhost:8000`        |
| `OAUTH2_JWT_ALG`                  | ID token signing algorithm           | `RS256`                                           |
| `OAUTH2_JWT_SECRET_KEY`           | OIDC signing secret (disposable)     | Any 32+ char random string                        |
| `OIDC_SIGNING_BACKEND`            | Signing backend                      | `database`                                        |
| `SESSION_MIDDLEWARE_SECRET_KEY`   | Session cookie secret (disposable)   | Any 32+ char random string                        |
| `SESSION_COOKIE_HTTPS_ONLY`       | HTTPS-only cookies                   | `false` (local conformance only)                  |
| `OAUTH2_TOKEN_EXPIRES_IN`         | Access token lifetime in seconds     | `3600`                                            |
| `EMAIL_SENDER_MODE`               | Email delivery mode                  | `console` (prints tokens to stdout)               |
| `EMAIL_PUBLIC_BASE_URL`           | Base URL used in email links         | `http://localhost:8000`                           |
| `SMTP_FROM_EMAIL`                 | From address                         | `no-reply@satoidc.local`                          |
| `APP_ENV`                         | Runtime environment tag              | `development`                                     |
| `SATOIDC_ADMIN_USERNAME`          | Root user login (seed)               | `conformtest`                                     |
| `SATOIDC_ADMIN_EMAIL`             | Root user email (seed)               | `conformtest@satoidc.local`                       |
| `SATOIDC_ADMIN_PASSWORD`          | Root user password (seed)            | `ConformPass1!`                                   |

> All `OAUTH2_*` and `SESSION_*` names have `SATOIDC_*` aliases. See
> [docs/README.md](README.md) and
> [specs/contracts/runtime-config.md](../specs/contracts/runtime-config.md)
> for the full alias table.

---

## Local SQLite Startup Runbook

Use this path for a quick local conformance check with no Docker dependency.

### Step 1 — Create the conformance `.env` file

```bash
cd satoidc
cat > .env.conformance << 'EOF'
DATABASE_URL=sqlite+aiosqlite:///conformance.db
SYNC_DATABASE_URL=sqlite:///conformance.db
OAUTH2_JWT_ISS=http://localhost:8000
OAUTH2_JWT_ALG=RS256
OAUTH2_JWT_SECRET_KEY=conformance-disposable-secret-000000001
OIDC_SIGNING_BACKEND=database
SESSION_MIDDLEWARE_SECRET_KEY=conformance-disposable-session-key-0001
SESSION_COOKIE_HTTPS_ONLY=false
OAUTH2_TOKEN_EXPIRES_IN=3600
EMAIL_SENDER_MODE=console
EMAIL_PUBLIC_BASE_URL=http://localhost:8000
SMTP_FROM_EMAIL=no-reply@satoidc.local
APP_ENV=development
SATOIDC_ADMIN_USERNAME=conformtest
SATOIDC_ADMIN_EMAIL=conformtest@satoidc.local
SATOIDC_ADMIN_PASSWORD=ConformPass1!
EOF
```

### Step 2 — Apply migrations and bootstrap the database

```bash
cd satoidc
set -a && source .env.conformance && set +a
poetry run alembic upgrade head
poetry run python -m setup_wizard.bootstrap --database-state
```

On Windows (PowerShell):

```powershell
cd satoidc
Get-Content .env.conformance | ForEach-Object {
    if ($_ -match '^([^#=]+)=(.*)$') {
        [System.Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
    }
}
poetry run alembic upgrade head
poetry run python -m setup_wizard.bootstrap --database-state
```

### Step 3 — Start the conformance instance

```bash
cd satoidc
set -a && source .env.conformance && set +a
poetry run task run
```

The server starts at `http://localhost:8000`. The bootstrap mechanism creates
the `conformtest` root user during Step 2 if no root/admin permission exists
yet.

### Step 4 — Register the conformance client

Log in at `http://localhost:8000` with:

- Username: `conformtest`
- Password: `ConformPass1!`

Navigate to `http://localhost:8000/create_client` and register the client(s)
described in the [Seed Data](#seed-data) section. Note the generated
`client_id` and `client_secret` (for the confidential client).

---

## PostgreSQL Startup Notes

The repository does not currently include a checked-in Docker Compose stack.
For PostgreSQL-backed conformance runs, provision a disposable PostgreSQL
database with your local container or hosting tooling, then use the same
SQLite runbook with PostgreSQL URLs:

```bash
DATABASE_URL=postgresql+psycopg://conform_user:conform_password@localhost:5432/conform_db
SYNC_DATABASE_URL=postgresql+psycopg://conform_user:conform_password@localhost:5432/conform_db
```

Run `poetry run alembic upgrade head` and
`poetry run python -m setup_wizard.bootstrap --database-state` against that
database before starting SatOIDC.

---

## Smoke Verification Checklist

Run these checks after startup to confirm the instance is ready before
pointing the conformance suite at it.

### Discovery endpoint

```bash
curl -s http://localhost:8000/.well-known/openid-configuration | python3 -m json.tool
```

Expected fields:

```json
{
  "issuer": "http://localhost:8000",
  "authorization_endpoint": "http://localhost:8000/authorize",
  "token_endpoint": "http://localhost:8000/oauth/token",
  "userinfo_endpoint": "http://localhost:8000/oauth/userinfo",
  "jwks_uri": "http://localhost:8000/.well-known/jwks.json",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "email", "profile"],
  "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
  "code_challenge_methods_supported": ["S256"]
}
```

Verify:

- `issuer` matches the `OAUTH2_JWT_ISS` value you configured.
- `jwks_uri` uses the same host/port.
- No implicit or hybrid `response_types` are listed.

### JWKS endpoint

```bash
curl -s http://localhost:8000/.well-known/jwks.json | python3 -m json.tool
```

Expected:

- At least one key object with `"kty": "RSA"`, `"alg": "RS256"`, and a stable
  `"kid"` value.

### Authorization endpoint reachability

```bash
curl -o /dev/null -w "%{http_code}" \
  "http://localhost:8000/authorize?response_type=code&client_id=<CLIENT_ID>&redirect_uri=<REDIRECT_URI>&scope=openid&state=smoke"
```

Replace `<CLIENT_ID>` and `<REDIRECT_URI>` with the registered conformance
client values. Expected HTTP status is `200` (the login page renders) or `302`
(redirect to login). A `400` or `500` indicates a client registration or
configuration issue.

### Token endpoint health (no-op check)

```bash
curl -s -o /dev/null -w "%{http_code}" \
  -X POST http://localhost:8000/oauth/token \
  -d "grant_type=authorization_code&code=invalid&redirect_uri=x"
```

Expected status: `400` (invalid request rejected). A `500` indicates a server
configuration error.

---

## Running the OpenID Foundation Conformance Suite

The [OpenID Foundation conformance suite](https://openid.net/certification/)
is available as:

- **Hosted**: `https://www.certification.openid.net/` (requires internet
  access from your SatOIDC instance or ngrok tunnelling).
- **Self-hosted**: Docker image `openid-foundation/conformance-suite`
  (see [the OIDF conformance suite repository](https://gitlab.com/openid/conformance-suite)
  for instructions).

### Configuration values for the suite

| Suite field              | Value                                                   |
| ------------------------ | ------------------------------------------------------- |
| Provider URL / Issuer    | `http://localhost:8000` (or your tunnel URL)            |
| Discovery URL            | `http://localhost:8000/.well-known/openid-configuration`|
| Client ID                | ID from Step 4 of the runbook above                     |
| Client secret            | Secret from Step 4 (confidential client only)           |
| Redirect URI             | As registered                                           |
| Username                 | `conformtest`                                           |
| Password                 | `ConformPass1!`                                         |
| Scope                    | `openid email profile`                                  |

### Recommended test plan

1. Run **Basic OP** — covers discovery, JWKS, authorization code, and token
   exchange.
2. Run **Basic OP with PKCE** — verifies S256 challenge/verifier flow.
3. Record pass/fail results in a dated report file (see
   [Recording Results](#recording-results)).

---

## Recording Results

Store results as a dated Markdown file under `docs/conformance-results/`:

```
docs/conformance-results/YYYY-MM-DD-basic-op.md
```

Include the following in the report:

- Date and operator running the test.
- SatOIDC version/git commit SHA.
- Conformance suite version (hosted or self-hosted).
- Target profile and configuration summary.
- Pass/fail/skip count per test.
- Any known deviations with references to `docs/known-issues.md` or open specs.

> **Do not commit** the conformance `.env.conformance*` files, the conformance
> database files, or any OAuth2 client secrets to version control.

---

## Known Limitations

| Limitation                                | Notes                                                      |
| ----------------------------------------- | ---------------------------------------------------------- |
| Implicit and hybrid flows                 | Not advertised in discovery; not in scope for this profile.|
| Dynamic client registration               | Not implemented; clients must be registered via the UI.    |
| Formal OIDF certification submission      | Not an immediate requirement; see the conformance spec.    |
| Internet-accessible issuer for hosted suite | Requires a tunnel (e.g. ngrok) when running locally.    |
| Email verification for test user          | Bootstrap sets `email_verified=True` automatically.        |

---

## Security Notes

- Use **disposable secrets** for all conformance runs. Never copy production
  credentials into conformance configuration.
- Delete `conformance.db` (or drop the conformance PostgreSQL database) after
  each testing session.
- Do not push conformance `.env` files or database files to version control.
- If using the hosted OIDF suite, expose your local instance only through a
  short-lived tunnel and shut it down after the test.
