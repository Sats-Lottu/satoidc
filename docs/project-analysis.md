# SatOIDC Project Analysis

Updated: 2026-05-06

## Summary

SatOIDC is a Python OpenID Connect Provider built with FastAPI, NiceGUI, Authlib, SQLAlchemy, Alembic, and Poetry. It aims to provide OAuth2/OIDC authentication while adding Bitcoin/Lightning login through LNURL-auth.

The current implementation is an early application prototype with real protocol integration pieces, a UI surface, database models, migrations, Docker deployment, and OIDC client examples. The main technical debt is around tests, permission consistency, security hardening, and protocol contract validation.

## Repository Layout

- `README.md`: project overview, setup notes, endpoint list, roadmap. It currently renders mojibake in this shell session and has a RS256/ES256 mismatch.
- `compose.yaml`: Postgres plus SatOIDC service.
- `satoidc/`: Python project root for Poetry.
- `satoidc/satoidc/`: application package.
- `satoidc/satoidc/auth/`: password hashing, authorization middleware, OAuth2/OIDC grants, LNURL helpers.
- `satoidc/satoidc/fastapi_oauth2/`: local adapter layer that makes Authlib work with FastAPI/Starlette requests.
- `satoidc/satoidc/models/`: SQLAlchemy models and session setup.
- `satoidc/satoidc/routes/`: NiceGUI and FastAPI routes.
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
- Compile sanity check: `cd satoidc; poetry run python -m compileall satoidc setup_wizard tests`
- Public client example: `cd satoidc; poetry run task start_public_client <client-id>`

## Application Startup

`satoidc/satoidc/__init__.py` creates the FastAPI app, adds `AuthMiddleware`, adds Starlette `SessionMiddleware`, configures Authlib, includes all routers, and mounts NiceGUI with `ui.run_with(app, title="SatOIDC - Identity Service")`.

Important behavior:

- Session cookie name is `client_session`.
- Session middleware uses `same_site="lax"` and `https_only=False`.
- OAuth config uses environment settings for issuer, algorithm, and token expiry.
- The app generates an RSA JWK in memory at import time in `auth/oauth2.py`.

## Configuration

`satoidc/satoidc/settings.py` loads `.env` through Pydantic settings.

Important settings:

- `DATABASE_URL`: async SQLAlchemy URL. Defaults to `sqlite+aiosqlite:///satoidc.db`.
- `SYNC_DATABASE_URL`: sync SQLAlchemy URL. Defaults to `sqlite:///satoidc.db`.
- `LNURL_K1_TTL_SECONDS`: challenge lifetime. Defaults to `60`.
- `OAUTH2_JWT_ISS`: issuer. Defaults to `http://localhost:8000`.
- `OAUTH2_JWT_AUDIENCE`: defaults to `SatOIDC-clients`.
- `OAUTH2_JWT_SECRET_KEY`: configured but current ID token signing uses generated RSA `KEY`.
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
- `verified`: replay guard.
- timestamps.

### OAuth2 Tables

Authlib mixins back:

- `OAuth2Client`
- `OAuth2AuthorizationCode`
- `OAuth2Token`

Authorization code expiry is hard-coded as `auth_time + 300 < time.time()`.

## OAuth2 And OIDC

`satoidc/satoidc/auth/oauth2.py` configures Authlib.

Supported grants/endpoints:

- Authorization Code Grant with OpenID Connect support.
- PKCE `CodeChallenge(required=True)`.
- Implicit Grant class registered.
- Hybrid Grant class registered.
- Refresh Token Grant class registered.
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

Scopes:

- `openid`
- `profile`
- `email`

UserInfo behavior:

- Always includes `sub`.
- Adds `email` if `email` scope is present.
- Adds `name` and `lnurl_pubkey` if `profile` scope is present.

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

- Marks an unverified, non-expired challenge as verified.
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
- `/register`: account registration with password form and optional LNURL QR.
- `/login`: password login and LNURL QR.
- `/logout`: clears session.
- `/forbidden`: access denied page.

Authenticated by middleware:

- `/profile`: profile, wallet status, permissions, and placeholder account actions.
- `/create_client`: OAuth2 client registration UI.
- `/dashboard/admin`: root-only by default through `page_security()`.
- `/dashboard/developer`: requires `developer` string permission, but current enum does not define developer.
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
- `poetry run task test`: failed because pytest collected `0` tests. Coverage reported `0%` and no data collected.

## Current Gaps And Risks

### High Priority

- Tests are effectively absent. `satoidc/tests/__init__.py` is the only test file.
- `login_post` redirects to submitted `redirect_to` without applying `safe_redirect`; `/register` does sanitize redirects. This may allow open redirects when `/login?redirect_to=...` is supplied directly.
- `auth/oauth2.py` generates the RSA signing key in memory on process start. Existing ID tokens can become unverifiable after restart, and multi-instance deployment will have inconsistent JWKS.
- `ResourceProtector.acquire_token` appears inconsistent with the local `FastAPIOAuth2Request` constructor. It calls `FastAPIOAuth2Request(request.method, request.url, {}, request.headers)`, but the constructor expects a single Starlette `Request`.

### Medium Priority

- Permission names are inconsistent. `PermissionsEnum` has `root`, `admin`, and `support`; the initial migration contains `DRAW_OPERATOR`; UI checks use `"developer"`, `"admin"`, and `"root"` strings.
- `LnurlAuthChallenge` is marked verified before signature validation; a bad signature consumes the challenge.
- `User.nickname` is non-null in the model, but LNURL registration creates a user with `nickname=None`.
- Refresh Token Grant is registered, but `create_bearer_token_generator` defaults `OAUTH2_REFRESH_TOKEN_GENERATOR` to `False`. Refresh token issuance needs explicit validation.
- README states RS256 in one section and ES256 in discovery example.
- README and examples render mojibake in this shell session, likely due to encoding mismatch in stored files or terminal decoding.

### Lower Priority

- `dashboard.py` has placeholder menu text `asdf`.
- `profile.py` contains placeholder button actions implemented as notifications.
- `create_client.py` has little validation and does not use `page_security(permissions=["developer"])`, so any logged-in user can reach it through middleware.
- `AuthMiddleware` makes all `/oauth` paths public, including consent POST. The POST has session and CSRF checks, so this is acceptable, but it should remain explicitly documented.
- `SessionMiddleware` uses `https_only=False`; production should set secure cookies behind HTTPS.

## Suggested Documentation Next Steps

- Normalize README encoding and protocol claims.
- Add first SDD specs for login redirect safety, persistent JWKS, permissions model, and LNURL-auth challenge lifecycle.
- Add tests for validators, `safe_redirect`, LNURL signature/challenge behavior, OAuth metadata, and login flow.
- Add a protocol contract document for OIDC discovery, JWKS, token, userinfo, and LNURL callback.

## Related Files

- `docs/architecture.md`
- `docs/known-issues.md`
- `specs/index.md`
- `agent-memory/index.md`
- `agent-memory/architecture.md`
- `agent-memory/risks.md`
