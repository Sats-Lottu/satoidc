# SatOIDC Project Analysis

Updated: 2026-05-16

## Summary

SatOIDC is a Python OpenID Connect Provider built with FastAPI, NiceGUI, Authlib, SQLAlchemy, Alembic, and Poetry. It aims to provide OAuth2/OIDC authentication while adding Bitcoin/Lightning login through LNURL-auth.

The current implementation is a beta-stage identity provider with real protocol integration pieces, a UI surface, database models, migrations, Docker deployment, OIDC client examples, unit/integration tests, and browser e2e coverage for the priority OAuth and UI flows. The active execution backlog now tracks open production-hardening, account recovery, testing, observability, and cleanup work; completed backlog items are summarized separately in `docs/priority-execution-history.md`.

## Repository Layout

- `README.md`: project overview, setup notes, endpoint list, roadmap, and documentation entry points.
- `AGENTS.md`: canonical AI-agent instructions and documentation map.
- `docs/README.md`: documentation index.
- `compose.yaml`: Postgres plus SatOIDC service.
- `satoidc/`: Python project root for Poetry.
- `satoidc/satoidc/`: application package.
- `satoidc/satoidc/auth/`: password hashing, authorization middleware, OAuth2/OIDC grants, LNURL helpers.
- `satoidc/satoidc/fastapi_oauth2/`: local adapter layer that makes Authlib work with FastAPI/Starlette requests.
- `satoidc/satoidc/models/`: SQLAlchemy models and session setup.
- `satoidc/satoidc/routes/`: NiceGUI and FastAPI routes.
- `satoidc/satoidc/schemas/`: Pydantic request/form schemas used by API and browser form endpoints.
- `satoidc/setup_wizard/`: first root-user setup app.
- `satoidc/migrations/`: Alembic migrations.
- `examples/`: NiceGUI relying-party clients.
- `specs/`: Spec-Driven Development workspace.
- `agent-memory/`: durable agent memory.

## Runtime Stack

- Python: `>=3.11,<4.0`
- Web framework: FastAPI
- UI framework: NiceGUI
- OAuth/OIDC: Authlib plus local FastAPI adapter
- ORM: SQLAlchemy async plus a separate sync engine for Authlib helpers
- Migrations: Alembic
- Databases: SQLite by default, Postgres in Compose
- Password hashing: `pwdlib[argon2]`
- LNURL: `bech32`, `ecdsa`, `segno`

## Commands

- Install: `cd satoidc; poetry install`
- Run migrations: `cd satoidc; poetry run alembic upgrade head`
- Run dev server: `cd satoidc; poetry run task run`
- Run tests: `cd satoidc; poetry run task test`
- Install Playwright browser: `cd satoidc; poetry run task playwright_install`
- Run browser e2e tests: `cd satoidc; poetry run task test_e2e`
- Run lint: `cd satoidc; poetry run ruff check`
- Compile sanity check: `cd satoidc; poetry run python -m compileall satoidc setup_wizard tests`
- Public client example: `cd satoidc; poetry run task start_public_client <client-id>`

## Application Startup

`satoidc/satoidc/main.py` creates the FastAPI app, adds `AuthMiddleware`, adds Starlette `SessionMiddleware`, configures Authlib, includes all routers, and mounts NiceGUI with `ui.run_with(app, title="SatOIDC - Identity Service")`.

Important behavior:

- Session cookie name is `client_session`.
- Session middleware uses `same_site="lax"` and environment-driven HTTPS-only cookies.
- OAuth config uses environment settings for issuer, algorithm, and token expiry.
- OIDC signing keys are persisted in the database, loaded at startup, and exposed through JWKS with active/validating/retired key states.

## Configuration

`satoidc/satoidc/settings.py` loads `.env` through Pydantic settings.

Important settings:

- `DATABASE_URL`: async SQLAlchemy URL. Defaults to `sqlite+aiosqlite:///satoidc.db`.
- `SYNC_DATABASE_URL`: sync SQLAlchemy URL. Defaults to `sqlite:///satoidc.db`.
- `LNURL_K1_TTL_SECONDS`: challenge lifetime. Defaults to `60`.
- `OAUTH2_JWT_ISS`: issuer. Defaults to `http://localhost:8000`.
- `OAUTH2_JWT_AUDIENCE`: defaults to `SatOIDC-clients`.
- `OAUTH2_JWT_SECRET_KEY`: encrypts persisted OIDC private JWK material.
- `OAUTH2_JWT_ALG`: defaults to `RS256`.
- `OAUTH2_TOKEN_EXPIRES_IN`: defaults to `300`.
- `SESSION_MIDDLEWARE_SECRET_KEY`: session signing secret.

## Database Model

Models are declared in `satoidc/satoidc/models/__init__.py` using SQLAlchemy mapped dataclasses where possible.

### `User`

Fields:

- `id`: UUID primary key.
- `lnurl_pubkey`: unique nullable wallet public key.
- `email`: unique nullable email.
- `login`: unique nullable login.
- `password_hash`: nullable password hash.
- `nickname`: non-null string, default `Satoshi`.
- `is_active`: boolean, default `True`.
- `created_at`, `updated_at`: server timestamps.

Relationships:

- `permissions`: permissions assigned to the user.
- `granted_permissions`: permissions this user granted to others.

### `Permission`

Fields:

- `id`: integer primary key.
- `user_id`: user receiving permission.
- `granted_by`: optional user granting permission.
- `permission_type`: `PermissionsEnum`.
- `expiration_date`: optional expiration.
- `reason`: optional text.
- `disabled`: boolean.
- `created_at`: server timestamp.

Constraints:

- Unique `(user_id, permission_type)`.

### `LnurlAuthChallenge`

Fields:

- `k1`: primary key, 32-byte hex challenge.
- `user_id`: optional user tied to challenge.
- `action`: `register`, `login`, `link`, or `auth` by convention.
- `consumed`: replay guard.
- timestamps.

### OAuth2 Tables

Authlib mixins back:

- `OAuth2Client`
- `OAuth2AuthorizationCode`
- `OAuth2Token`

Additional operational tables include:

- `PermissionRequest`: stores user requests for elevated permissions such as developer access.
- `OidcSigningKey`: stores encrypted signing JWKs and key lifecycle state.
- `OidcSigningKeyAuditEvent`: records signing-key lifecycle operations.

Authorization code expiry is hard-coded as `auth_time + 300 < time.time()`.

## OAuth2 And OIDC

`satoidc/satoidc/auth/oauth2.py` configures Authlib.

Supported grants/endpoints:

- Authorization Code Grant with OpenID Connect support.
- PKCE `CodeChallenge(required=True)`.
- Refresh Token Grant registered with refresh token generation enabled.
- Introspection endpoint.
- Revocation endpoint.
- Bearer token resource protection.

OIDC metadata route:

- `GET /.well-known/openid-configuration`

Token/user routes:

- `POST /oauth/authorize`
- `POST /oauth/token`
- `POST /oauth/introspect`
- `POST /oauth/revoke`
- `GET /oauth/userinfo`
- `GET /.well-known/jwks.json`

Schemas are centralized in `satoidc/satoidc/schemas/`; the legacy
`auth/lnurl_schemas.py` compatibility re-export has been removed.

Scopes:

- `openid`
- `profile`
- `email`

UserInfo behavior:

- Always includes `sub`.
- Adds `email` if `email` scope is present.
- Adds `name` and `lnurl_pubkey` if `profile` scope is present.
- Passes scope values to Authlib as a list for bearer-resource compatibility.
- Full browser authorization-code e2e coverage exists for public PKCE and confidential `client_secret_post` clients.

## LNURL-auth

LNURL helpers live in `satoidc/satoidc/auth/lnurl.py`.

Core pieces:

- `url_encode(url)`: converts callback URL to uppercase bech32 `lnurl`.
- `verify(k1, key, sig)`: verifies DER ECDSA signature over `k1` with secp256k1 key.
- `lnurl_auth_events`: NiceGUI event emitter used to notify UI pages after wallet callback.
- `lnurl_auth_temp_storage`: NiceGUI general storage for transient login linkage.

Callback route:

- `GET /auth/lnurl/callback`

Callback behavior:

- Marks an unconsumed, non-expired challenge as consumed.
- Checks action matches.
- Verifies signature.
- For `register`, creates a user when no user exists for the key.
- For `login`, requires an existing user.
- For `link`, assigns the key to the challenge user.
- For `auth`, returns success for stateless authorization.
- Emits `{k1, user_id}` through `lnurl_auth_events`.

## UI Routes

Public:

- `/`: landing page.
- `/register`: account registration page with password form and optional LNURL QR.
- `POST /register`: validates registration, creates a user, stores `request.session["user_id"]`, and redirects already logged in.
- `/login`: password login and LNURL QR.
- `POST /login`: nonce-protected password login.
- `/logout`: clears session.
- `/forbidden`: access denied page.

Authenticated by middleware:

- `/profile`: profile, editable nickname/email/password, wallet link/relink/unlink, permission state, and developer permission request workflow.
- `/create_client`: OAuth2 client registration UI with access control, metadata validation, and one-time credential display.
- `/dashboard/admin`: root/admin dashboard for permission requests, user/client metrics, and approve/deny actions.
- `/dashboard/developer`: client management dashboard with edit, copy, rotate secret, disable, and delete flows.
- `/authorize`: OIDC consent UI.

## Setup Wizard

`satoidc/setup_wizard/__main__.py` checks whether a root permission exists. If no root user exists, it starts a NiceGUI setup app on port `8000`.

Root creation paths:

- Form registration creates a user plus `PermissionsEnum.ROOT`.
- LNURL registration creates or resolves a user, then grants `ROOT`.
- After root creation, the wizard shuts down and the container entrypoint starts the main app.

## Docker And Compose

`compose.yaml` defines:

- `database`: Postgres 16 with `app_user`, `app_db`, and `app_password`.
- `satoidc`: builds from `satoidc/DockerFile`, runs `entrypoint.sh`, waits for the database healthcheck, and maps container port `8000` to `${SATOIDC_PORT:-8000}`.

`entrypoint.sh`:

1. Runs Alembic migrations.
2. Runs setup wizard if no root user exists.
3. Starts FastAPI on `0.0.0.0:8000`.

## Examples

`examples/basic_client.py`:

- Confidential OIDC client.
- Uses `client_secret`.
- Uses Authlib Starlette client.
- Validates `exp`, `aud`, and `iss` from returned user info.

`examples/public_client.py`:

- Public OIDC client.
- Takes `--client-id`.
- Uses `token_endpoint_auth_method="none"`.
- Requests PKCE with `code_challenge_method="S256"`.

## Validation Results

Run on 2026-05-06:

- `poetry run python -m compileall satoidc setup_wizard tests`: passed.
- `poetry run ruff check`: passed after adding time-sensitive tests.
- `poetry run task test`: passed with `33 passed, 10 deselected`; browser e2e tests are deselected by default.
- `poetry run task test_e2e`: passed with Playwright browser smoke/responsive tests.

Run on 2026-05-08 after schema, registration, and coverage changes:

- `poetry run ruff check`: passed.
- `poetry run task test`: passed with `81 passed, 10 deselected` and 100% measured line coverage.
- `poetry run task test_e2e`: passed with `10 passed`.

Run on 2026-05-15 after priority backlog completion:

- `poetry run ruff check`: passed.
- `poetry run task test`: passed with `113 passed, 17 deselected`.
- `poetry run task test_e2e`: passed with `17 passed`.

## Current Gaps And Risks

### Production Hardening

- OIDC signing key persistence and rotation are implemented in the database. A future production deployment may still move private-key operations to Vault Transit or another external signing backend.
- `LnurlAuthChallenge.consumed` intentionally records callback consumption before signature validation as a replay-defense measure.
- LNURL registration now uses the default nickname `satoshi` for wallet-created
  users when no nickname is supplied.
- Refresh Token Grant has focused unit/integration coverage and browser coverage for refresh issuance, but still needs broader end-to-end revocation and reuse coverage.

### UX And Maintenance

- `create_client.py` validates metadata and uses page-level permission checks, but still uses notifications instead of inline field-level validation.
- Profile mutations currently use page-local NiceGUI interactions and supporting POST endpoints; future maintenance should decide whether to consolidate these flows.
- `AuthMiddleware` makes `/oauth` and paths below it public by exact or
  segment-boundary matching, including consent POST. The POST has session and
  CSRF checks, so this is acceptable, but it should remain explicitly
  documented.
- Production mode rejects placeholder secrets and requires secure session cookies.

## Suggested Documentation Next Steps

- Expand refresh-token revocation/reuse e2e coverage.
- Decide whether OIDC signing should move to an external signing backend for production.
- Add inline validation UX to the create-client form.
- Keep README, specs, and agent memory aligned when LNURL actions change.

## Related Files

- `docs/architecture.md`
- `docs/known-issues.md`
- `docs/changes-2026-05-08.md`
- `specs/index.md`
- `agent-memory/index.md`
- `agent-memory/architecture.md`
- `agent-memory/risks.md`
