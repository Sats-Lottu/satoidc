<p align="center">
  <img src="satoidc/statics/imgs/logo.png" alt="SatOIDC logo" width="120" />
</p>

<h1 align="center">SatOIDC</h1>

<p align="center">
  <strong>Satoshi OpenID Connect Provider</strong><br />
  Identity, OAuth2/OIDC and Lightning-native authentication for Bitcoin-first applications.
</p>

<p align="center">
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-blue.svg" /></a>
  <img alt="Python" src="https://img.shields.io/badge/python-3.11%2B-3776AB.svg" />
  <img alt="FastAPI" src="https://img.shields.io/badge/FastAPI-0.129-009688.svg" />
  <img alt="Status" src="https://img.shields.io/badge/status-beta-orange.svg" />
</p>

---

## Overview

**SatOIDC** is an OpenID Connect 1.0 Provider that combines traditional federated identity with Bitcoin/Lightning authentication through LNURL-auth.

The project implements an **OpenID Provider (OP)** with:

- OAuth2 Authorization Code Flow with OpenID Connect support.
- ID Token issuance with JWT/JWKS.
- PKCE support for public clients.
- UserInfo, discovery, introspection and revocation endpoints.
- Password-based login plus LNURL-auth login/registration flows.
- NiceGUI web interface for onboarding, login, consent, profile and client management.

SatOIDC is currently a **beta implementation**. The codebase contains the main protocol, UI, recovery, signing, and validation building blocks; the remaining work is focused on conformance, production observability, operational polish, and broader end-to-end coverage.

---

## Interface

The web UI is built with **NiceGUI** and follows the project interface conventions in [DESIGN.md](DESIGN.md).

Current screens include:

- Home and onboarding.
- Login with password or Lightning wallet.
- Account registration with terms acceptance.
- OAuth2/OIDC consent screen.
- User profile, email verification, password recovery and wallet status.
- Developer/admin dashboards.
- OAuth2 client registration.
- OAuth2 client management, secret rotation and permission request approval.

> Screenshots are not committed yet. The UI can be reviewed locally after running the development server.

---

## Architecture

```mermaid
flowchart LR
    Client["OIDC Client / Relying Party"]
    Browser["User Browser"]
    App["SatOIDC<br/>FastAPI + NiceGUI"]
    Authlib["Authlib<br/>OAuth2/OIDC Engine"]
    DB["Database<br/>SQLite or PostgreSQL"]
    Transit["OpenBao/Vault Transit<br/>optional signing backend"]
    Mail["Email Sender<br/>SMTP / console / disabled"]
    Wallet["Lightning Wallet"]

    Client --> Browser
    Browser --> App
    App --> Authlib
    Authlib --> DB
    App --> DB
    App --> Transit
    App --> Mail
    Browser --> Wallet
    Wallet --> App
```

Main implementation areas:

- `satoidc/satoidc/auth/`: OAuth2/OIDC, security and LNURL-auth helpers.
- `satoidc/satoidc/fastapi_oauth2/`: FastAPI/Starlette adapter for Authlib.
- `satoidc/satoidc/routes/`: FastAPI and NiceGUI routes.
- `satoidc/satoidc/models/`: SQLAlchemy models.
- `satoidc/migrations/`: Alembic migrations.
- `examples/`: relying-party client examples. See [examples/README.md](examples/README.md).
- `satoidc/`: Poetry project root. See [satoidc/README.md](satoidc/README.md).

For a deeper technical map, start from [docs/README.md](docs/README.md), especially [docs/project-analysis.md](docs/project-analysis.md), [docs/architecture.md](docs/architecture.md), and the active [priority execution backlog](docs/priority-execution-backlog.md).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) before submitting changes. SatOIDC
accepts AI-assisted work only when a human contributor reviews, understands,
validates, and discloses the assistance. Use the pull request template and
include `Assisted-by:` metadata for meaningful AI-generated or AI-assisted
content.

---

## Protocol Support

| Capability                | Status         | Notes                                                                        |
| ------------------------- | -------------- | ---------------------------------------------------------------------------- |
| OAuth2 Authorization Code | Implemented    | Main supported flow.                                                         |
| OpenID Connect ID Token   | Implemented    | Signed with database or OpenBao/Vault-compatible Transit RS256 keys and stable `kid` headers. |
| PKCE                      | Implemented    | Required for the Authorization Code Grant.                                   |
| Discovery                 | Implemented    | Served at `/.well-known/openid-configuration`.                               |
| JWKS                      | Implemented    | Publishes active and validating public signing keys with stable `kid` values. |
| UserInfo                  | Implemented    | Returns claims based on granted scopes.                                      |
| Introspection             | Implemented    | Authlib endpoint registered.                                                 |
| Revocation                | Implemented    | Authlib endpoint registered.                                                 |
| Refresh Token Grant       | Implemented    | Registered with refresh token issuance enabled and covered by focused tests. |
| LNURL-auth                | Implemented    | Login, register, link and auth actions exist.                                |
| Implicit/Hybrid           | Not advertised | Not registered for the current provider contract.                            |

---

## Endpoints

| Endpoint | Description |
| --- | --- |
| `/authorize` | Authorization consent page. |
| `/oauth/authorize` | Authorization decision POST. |
| `/oauth/token` | Token endpoint. |
| `/oauth/userinfo` | UserInfo endpoint. |
| `/oauth/introspect` | Token introspection endpoint. |
| `/oauth/revoke` | Token revocation endpoint. |
| `/.well-known/openid-configuration` | OIDC discovery metadata. |
| `/.well-known/jwks.json` | Public signing keys. |
| `/auth/lnurl/callback` | LNURL-auth wallet callback. |
| `/verify-email` | Email verification token endpoint. |
| `/forgot-password` | Password recovery request page. |
| `/reset-password` | Password reset token page. |
| `/profile` | Signed-in account profile page. |
| `/dashboard` | Developer dashboard. |
| `/dashboard/admin` | Admin dashboard. |
| `/create_client` | OAuth2 client registration page. |

---

## Quick Start

```bash
git clone https://github.com/Sats-Lottu/satoidc.git
cd satoidc/satoidc
poetry install
poetry run alembic upgrade head
poetry run task run
```

The development server is available at:

```text
http://localhost:8000
```

The first deployment path should run the setup wizard to create a root user
when no root permission exists. You can also start the setup wizard manually:

```bash
poetry run task setup_wizard
```

After a root user exists, manual setup wizard access requires root credentials
before showing service setup checks. You can sign in with root login/email and
password credentials, or with a Lightning wallet linked to a root account.

If a local SQLite database reports an Alembic revision that is not present in
`migrations/versions/`, follow
[Local Development Troubleshooting](docs/local-development-troubleshooting.md)
before deleting or stamping the database.

---

## Configuration

Create a `.env` file inside `satoidc/` for local development:

```env
DATABASE_URL=sqlite+aiosqlite:///satoidc.db
SYNC_DATABASE_URL=sqlite:///satoidc.db
OAUTH2_JWT_ISS=http://localhost:8000
OAUTH2_JWT_ALG=RS256
OAUTH2_JWT_SECRET_KEY=CHANGE_ME_TO_A_LONG_RANDOM_SECRET
OIDC_SIGNING_BACKEND=database
OAUTH2_TOKEN_EXPIRES_IN=300
SESSION_MIDDLEWARE_SECRET_KEY=CHANGE_ME_TO_A_LONG_RANDOM_SECRET
EMAIL_SENDER_MODE=console
EMAIL_PUBLIC_BASE_URL=http://localhost:8000
SMTP_FROM_EMAIL=no-reply@satoidc.local
```

For production-like deployments, configure PostgreSQL and strong secrets through the environment.
When production starts with placeholder generated-owned secrets, bootstrap can
persist replacement values to `SETUP_GENERATED_SECRETS_PATH`; the Compose stack
defaults that path to `/app/generated/secrets.env` on a persistent volume.
For hardened signing, set `OIDC_SIGNING_BACKEND=transit` and configure the
Vault-compatible Transit endpoint and token through environment variables.

---

## Docker Compose

```bash
docker compose up --build
```

The compose stack starts:

- PostgreSQL 16.
- SatOIDC with migrations, setup wizard and FastAPI runtime on `http://localhost:8000`.

The stack reads optional overrides from `.env`; use `.env.example` as the baseline for ports, database credentials and secrets. PostgreSQL has a healthcheck, so the application waits for the database before running migrations.

For self-hosted operations, follow the [operator runbook](docs/operations/runbook.md)
for backup, restore, upgrade, migration failure handling, health checks and
incident response. Use [reverse proxy operations](docs/operations/reverse-proxy.md)
for TLS, forwarded headers and delegated auth rate limiting. Use
[email operations](docs/operations/email.md) for SMTP/console/disabled delivery
modes and recovery token troubleshooting, and
[Transit signing operations](docs/operations/transit.md) for OpenBao/Vault
Transit setup and signing failure handling.

## CI/CD

GitHub Actions workflows live in `.github/workflows/`:

- `ci.yaml` runs Ruff, the default test suite and a Docker image build on pushes and pull requests.
- `deploy-coolify.yaml` triggers a Coolify deployment after CI succeeds on `main`, or manually from GitHub Actions.

See [docs/deployment/vps.md](docs/deployment/vps.md) for the required GitHub Secrets and VPS setup.

---

## OIDC Discovery

```bash
curl http://localhost:8000/.well-known/openid-configuration
```

Expected metadata includes:

```json
{
  "issuer": "http://localhost:8000",
  "authorization_endpoint": "http://localhost:8000/authorize",
  "token_endpoint": "http://localhost:8000/oauth/token",
  "userinfo_endpoint": "http://localhost:8000/oauth/userinfo",
  "jwks_uri": "http://localhost:8000/.well-known/jwks.json",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "code_challenge_methods_supported": ["S256"]
}
```

---

## Client Examples

NiceGUI relying-party examples are available in [examples](examples/):

| Example | Focus |
| --- | --- |
| `basic_client.py` | Confidential client using `client_secret`. |
| `public_client.py` | Public client using PKCE and `token_endpoint_auth_method=none`. |

Public client example:

```bash
cd satoidc
poetry run task start_public_client <client-id>
```

---

## Tests And Validation

Current implemented commands:

```bash
cd satoidc
poetry run task test
```

The default test task excludes browser e2e, container-backed, load and slow
tests. Time-sensitive behavior such as authorization-code expiration,
refresh-token windows and LNURL challenge expiration is covered with
`freezegun`.

Browser e2e tests are separate from the default test task:

```bash
cd satoidc
poetry run task playwright_install
poetry run task test_e2e
```

Additional test-layer commands are available for focused verification:

- `poetry run task test_unit`
- `poetry run task test_property`
- `poetry run task test_api_security`
- `poetry run task test_integration`
- `poetry run task test_load`
- `poetry run task test_all`

Useful sanity check:

```bash
cd satoidc
poetry run python -m compileall satoidc setup_wizard tests
```

---

## Roadmap

### Current State

- [x] FastAPI/NiceGUI application shell.
- [x] SQLAlchemy models and Alembic migration baseline.
- [x] OAuth2/OIDC Authorization Code foundation.
- [x] OIDC discovery, JWKS and UserInfo endpoints.
- [x] LNURL-auth login/register callback flow.
- [x] Setup wizard for initial root user.
- [x] NiceGUI relying-party examples.
- [x] Spec-Driven Development workspace in `specs/`.
- [x] Project architecture and risk documentation in `docs/`.
- [x] Unit/integration test baseline for validators, OAuth/OIDC metadata, grants, LNURL-auth, setup wizard, security helpers and time-sensitive behavior.
- [x] Browser e2e smoke/responsive test baseline for public pages and well-known endpoints.

### Production Hardening

- [x] Expand full OAuth browser authorization-code e2e coverage, including real client redirects and token exchange.
- [x] Replace process-local JWT signing key with persistent key material and a key-rotation plan.
- [x] Normalize the permission model across enum, migration, UI and access checks.
- [x] Harden login redirect handling and add regression tests for open redirect prevention.
- [x] Rename LNURL challenge state from `verified` to `consumed` while preserving the current replay-defense behavior where every callback attempt consumes the challenge.
- [ ] Broaden refresh token issuance and revocation coverage into end-to-end client flows.
- [x] Make session/cookie settings production-aware, including HTTPS-only cookies.
- [x] Harden public route boundary matching for lookalike protected paths.
- [x] Add OpenBao/Vault-compatible external signing backend.
- [ ] Add sanitized operational logging for auth, OIDC, LNURL and UI mutation failures.
- [x] Validate the SQLite/PostgreSQL support matrix.

### Product And Developer Experience

- [x] Finish profile account actions: nickname, email, password, and wallet link/relink/unlink.
- [x] Finish developer dashboard and OAuth2 client management.
- [x] Add client metadata validation for redirect URIs, scopes, grant types and auth methods.
- [ ] Add screenshots to this README once the UI stabilizes.
- [x] Normalize text encoding in README/examples/legal docs where mojibake appears.
- [x] Implement verified-email account recovery and password reset.
- [x] Refactor persistence-heavy NiceGUI actions into service helpers.
- [x] Expand the quality-testing baseline with container-backed API and
  PostgreSQL coverage.

### Future Protocol Work

- [ ] Publish a stable OIDC contract and conformance checklist.
- [x] Expose discovery at root `/.well-known/openid-configuration`.
- [ ] Evaluate Nostr identity integration.
- [ ] Revisit implicit/hybrid support before advertising those flows.
- [ ] Track Authlib/FastAPI ecosystem support and simplify the adapter layer when viable.

---

## Security Notes

- Use HTTPS in production.
- Use strong environment secrets.
- Persisted database signing keys are available for development and small deployments; prefer OpenBao/Vault-compatible Transit for hardened production signing.
- Treat local SQLite files and NiceGUI storage as development state.
- Review [docs/known-issues.md](docs/known-issues.md) before production deployment.

---

## Project Methodology

SatOIDC uses:

- [AGENTS.md](AGENTS.md) for agent-facing project instructions.
- [DESIGN.md](DESIGN.md) for web interface conventions.
- [docs](docs/README.md) for architecture, analysis and known issues.
- [docs/priority-execution-backlog.md](docs/priority-execution-backlog.md) for active temporary execution tasks.
- [docs/priority-execution-history.md](docs/priority-execution-history.md) for completed backlog summaries.
- [specs](specs/README.md) and [specs/index.md](specs/index.md) for Spec-Driven Development.
- [agent-memory](agent-memory/index.md) for durable project memory.

---

## License

MIT License. See [LICENSE](LICENSE).

---

## Philosophy

> Don't trust. Verify.

SatOIDC aims to connect traditional federated identity with individual sovereignty principles inspired by Satoshi Nakamoto.
