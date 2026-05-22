# Runtime Configuration Contract

Status: draft
Area: Runtime/Configuration
Last Updated: 2026-05-18

## Intent

Describe the current settings, defaults, and startup configuration used by the
SatOIDC FastAPI/NiceGUI application.

## Settings Source

Runtime settings are loaded by `satoidc/satoidc/settings.py` using Pydantic
settings.

The app reads `.env` from the current working directory with UTF-8 encoding.

## Current Implementation

The current application accepts the Pydantic field names below directly from
process environment variables or `.env`. `SATOIDC_PORT` is consumed by Compose
only to choose the host port and is not read by the Python settings object.

Current precedence is:

1. explicit values passed to `Settings(...)` by tests or internal callers;
2. process environment variables using current names;
3. `.env` values from the current working directory using current names;
4. defaults declared in `satoidc/satoidc/settings.py`.

Current runtime code does not resolve `SATOIDC_*` aliases or `_FILE` variables.
The only generated-file behavior currently documented here is
`SETUP_GENERATED_SECRETS_PATH`, which points the bootstrap/entrypoint flow at a
shell env file containing generated current-name secret exports.

## Compatibility And Precedence Contract

The long-term operator interface is the `SATOIDC_*` namespace because it is
product-scoped and clearer for self-hosted deployments. Existing deployments
that use current names remain supported during the migration window.

Future configuration resolution must use this precedence for each logical
setting:

1. `SATOIDC_*` direct environment variable.
2. `SATOIDC_*_FILE` when the direct `SATOIDC_*` value is absent and the setting
   supports file-mounted secrets.
3. Current direct environment variable.
4. Current `_FILE` variable when the current direct value is absent and the
   setting supports file-mounted secrets.
5. Persisted database configuration for wizard-owned non-secret settings.
6. Safe default for the current environment.
7. Setup Wizard input, which creates or updates persisted configuration but
   cannot override an environment-controlled setting.

If both a direct variable and its `_FILE` form are set for the same namespace,
the direct value wins and startup should log a non-sensitive warning. If both
`SATOIDC_*` and current names are set for the same logical setting, the
`SATOIDC_*` value wins and startup should log a non-sensitive deprecation
warning for the current name. Secret values must never be logged.

Until alias support is implemented and covered by `satoidc/tests/test_settings.py`,
operators must use current names in production. The planned `SATOIDC_*` names in
the matrix below are contract targets, not currently accepted runtime inputs.

## Runtime Variable Matrix

Status meanings:

- `implemented`: accepted by current runtime code.
- `compose-only`: used by Compose, not by Python settings.
- `planned-alias`: future `SATOIDC_*` interface for an implemented setting.
- `planned`: future Setup Wizard or operator setting that has no current
  runtime equivalent.
- `implemented partial`: accepted by current runtime code but not yet used as
  the complete logical setting described by the future contract.
- `generated-path`: implemented bootstrap helper path for generated current
  secret exports.

| Logical setting | Current variable | Future variable | `_FILE` support | Secret | Required | Status | Migration note |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Instance name | `SERVICE_NAME` | `SATOIDC_INSTANCE_NAME` | no | no | optional | implemented / planned-alias | Future alias maps to `SERVICE_NAME`; keep current name during migration. |
| Public domain hint | `DOMAIN` | none | no | no | optional | implemented | Keep current name unless replaced by explicit public URL behavior. |
| Runtime environment | `APP_ENV` | `SATOIDC_APP_ENV` | no | no | optional | implemented / planned-alias | Future alias maps to `APP_ENV`; production checks still use `production` or `prod`. |
| Host port | none | `SATOIDC_PORT` | no | no | optional | compose-only | Compose maps host port to container port `8000`; runtime ignores it. |
| Compose database user | `POSTGRES_USER` | none | no | no | required for Compose PostgreSQL | compose-only | Compose uses this to initialize PostgreSQL and interpolate runtime database URLs. |
| Compose database password | `POSTGRES_PASSWORD` | none | future Compose secret only | yes | required for Compose PostgreSQL | compose-only | Compose uses this to initialize PostgreSQL and interpolate runtime database URLs. |
| Compose database name | `POSTGRES_DB` | none | no | no | required for Compose PostgreSQL | compose-only | Compose uses this to initialize PostgreSQL and interpolate runtime database URLs. |
| Public base URL | `EMAIL_PUBLIC_BASE_URL` partially | `SATOIDC_PUBLIC_BASE_URL` | no | no | yes in future setup | implemented partial / planned-alias | Future public URL should drive email links and setup validation; current fallback also uses request base URL or issuer. |
| OIDC issuer | `OAUTH2_JWT_ISS` | `SATOIDC_ISSUER` | no | no | required in production | implemented / planned-alias | Future alias maps to issuer; current name remains a backwards-compatible alias. |
| Async database URL | `DATABASE_URL` | `SATOIDC_DATABASE_URL` | yes, future only | maybe | required | implemented / planned-alias | Future alias maps to async SQLAlchemy URL; URL is secret only when it contains credentials. |
| Sync database URL | `SYNC_DATABASE_URL` | `SATOIDC_SYNC_DATABASE_URL` | yes, future only | maybe | required while Authlib remains sync | implemented / planned-alias | Future may derive sync URL from `SATOIDC_DATABASE_URL`; until then current pair must target the same database. |
| Session secret | `SESSION_MIDDLEWARE_SECRET_KEY` | `SATOIDC_SECRET_KEY` | yes, future only | yes | required in production | implemented / planned-alias | Future single app secret maps to session signing and any app-level crypto use that explicitly adopts it. |
| OIDC internal crypto secret | `OAUTH2_JWT_SECRET_KEY` | `SATOIDC_OIDC_SECRET_KEY` | yes, future only | yes | required for database signer | implemented / planned-alias | Future specific alias maps to OIDC key protection; if absent, implementation may derive from `SATOIDC_SECRET_KEY` for simple deployments, but current name remains supported during migration. |
| Session secure cookie flag | `SESSION_COOKIE_HTTPS_ONLY` | `SATOIDC_SESSION_COOKIE_HTTPS_ONLY` | no | no | required true in production | implemented / planned-alias | Future alias maps to explicit secure-cookie override; default remains environment-derived. |
| Generated secrets file | `SETUP_GENERATED_SECRETS_PATH` | `SATOIDC_GENERATED_SECRETS_PATH` | no | no | optional | generated-path / planned-alias | Current path points to a shell env file with generated current-name secrets. |
| LNURL challenge TTL | `LNURL_K1_TTL_SECONDS` | `SATOIDC_LNURL_K1_TTL_SECONDS` | no | no | optional | implemented / planned-alias | Future alias maps to current QR/challenge lifetime. |
| LNURL Auth enablement | none | `SATOIDC_LNURL_AUTH_ENABLED` | no | no | optional | planned | Future wizard-owned feature flag; no current runtime switch exists. |
| OIDC audience | `OAUTH2_JWT_AUDIENCE` | `SATOIDC_OIDC_AUDIENCE` | no | no | optional | implemented / planned-alias | Future alias maps to configured audience value. |
| OIDC signing algorithm | `OAUTH2_JWT_ALG` | `SATOIDC_OIDC_SIGNING_ALG` | no | no | optional | implemented / planned-alias | Future alias maps to ID Token signing algorithm. v1 accepts `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, and `PS512`. |
| Access/ID token lifetime | `OAUTH2_TOKEN_EXPIRES_IN` | `SATOIDC_TOKEN_LIFETIME_SECONDS` | no | no | optional | implemented / planned-alias | Future alias maps to current token expiration value. |
| Refresh token lifetime | none | `SATOIDC_REFRESH_TOKEN_LIFETIME_SECONDS` | no | no | optional | planned | No current setting; add only with implementation and tests. |
| Default OIDC scopes | none | `SATOIDC_OIDC_DEFAULT_SCOPES` | no | no | optional | planned | Future wizard-owned client/protocol default. |
| Require PKCE | none | `SATOIDC_REQUIRE_PKCE` | no | no | optional | planned | Future policy setting for public clients. |
| Redirect URI policy | none | `SATOIDC_REDIRECT_URI_POLICY` | no | no | optional | planned | Future validation policy; no current runtime switch exists. |
| JWK rotation policy | none | `SATOIDC_JWK_ROTATION_POLICY` | no | no | optional | planned | Future policy setting layered over current key lifecycle. |
| JWKS cache TTL | `OIDC_JWKS_CACHE_TTL_SECONDS` | `SATOIDC_OIDC_JWKS_CACHE_TTL_SECONDS` | no | no | optional | implemented / planned-alias | Future alias maps to current JWKS cache setting. |
| Key retention margin | `OIDC_KEY_RETENTION_MARGIN_SECONDS` | `SATOIDC_OIDC_KEY_RETENTION_MARGIN_SECONDS` | no | no | optional | implemented / planned-alias | Future alias maps to current key retention safety margin. |
| Signing backend | `OIDC_SIGNING_BACKEND` | `SATOIDC_OIDC_SIGNING_BACKEND` | no | no | optional | implemented / planned-alias | Supported values remain `database` and `transit`. |
| Transit address | `OIDC_TRANSIT_ADDR` | `SATOIDC_OIDC_TRANSIT_ADDR` | no | no | required for transit | implemented / planned-alias | Future alias maps to Vault-compatible Transit base URL. |
| Transit token | `OIDC_TRANSIT_TOKEN` | `SATOIDC_OIDC_TRANSIT_TOKEN` | yes, future only | yes | required for transit | implemented / planned-alias | Prefer `_FILE` in production when supported. |
| Transit mount | `OIDC_TRANSIT_MOUNT` | `SATOIDC_OIDC_TRANSIT_MOUNT` | no | no | optional for transit | implemented / planned-alias | Future alias maps to Transit mount path. |
| Transit key name | `OIDC_TRANSIT_KEY_NAME` | `SATOIDC_OIDC_TRANSIT_KEY_NAME` | no | no | optional for transit | implemented / planned-alias | Future alias maps to Transit key name. |
| Email mode | `EMAIL_SENDER_MODE` | `SATOIDC_EMAIL_SENDER_MODE` | no | no | optional | implemented / planned-alias | Future alias maps to `disabled`, `console`, or `smtp`. |
| Email sender address | `SMTP_FROM_EMAIL` | `SATOIDC_EMAIL_SENDER` | no | no | optional | implemented / planned-alias | Future alias maps to sender address. |
| Verification token TTL | `EMAIL_VERIFICATION_TOKEN_TTL_SECONDS` | `SATOIDC_EMAIL_VERIFICATION_TOKEN_TTL_SECONDS` | no | no | optional | implemented / planned-alias | Future alias maps to current verification lifetime. |
| Reset token TTL | `EMAIL_RESET_TOKEN_TTL_SECONDS` | `SATOIDC_EMAIL_RESET_TOKEN_TTL_SECONDS` | no | no | optional | implemented / planned-alias | Future alias maps to current recovery lifetime. |
| Email token request interval | `EMAIL_TOKEN_MIN_REQUEST_INTERVAL_SECONDS` | `SATOIDC_EMAIL_TOKEN_MIN_REQUEST_INTERVAL_SECONDS` | no | no | optional | implemented / planned-alias | Future alias maps to current throttling interval. |
| SMTP host | `SMTP_HOST` | `SATOIDC_SMTP_HOST` | no | no | required for SMTP | implemented / planned-alias | Future alias maps to SMTP host. |
| SMTP port | `SMTP_PORT` | `SATOIDC_SMTP_PORT` | no | no | optional | implemented / planned-alias | Future alias maps to SMTP port. |
| SMTP username | `SMTP_USERNAME` | `SATOIDC_SMTP_USERNAME` | no | no | optional | implemented / planned-alias | Future alias maps to SMTP username. |
| SMTP password | `SMTP_PASSWORD` | `SATOIDC_SMTP_PASSWORD` | yes, future only | yes | optional | implemented / planned-alias | Prefer `_FILE` in production when supported. |
| SMTP implicit TLS | `SMTP_USE_TLS` | `SATOIDC_SMTP_TLS` | no | no | optional | implemented / planned-alias | Future alias maps to current implicit TLS flag. |
| SMTP STARTTLS | `SMTP_START_TLS` | `SATOIDC_SMTP_STARTTLS` | no | no | optional | implemented / planned-alias | Future alias maps to current STARTTLS flag. |
| Initial admin email | none | `SATOIDC_ADMIN_EMAIL` | no | no | required for future bootstrap | planned | Future non-interactive bootstrap variable; no current runtime support. |
| Initial admin username | none | `SATOIDC_ADMIN_USERNAME` | no | no | required for future bootstrap | planned | Future non-interactive bootstrap variable; no current runtime support. |
| Initial admin password | none | `SATOIDC_ADMIN_PASSWORD` | yes, future only | yes | required for future bootstrap | planned | Future non-interactive bootstrap secret; prefer `_FILE`. |
| Setup mode | none | `SATOIDC_SETUP_MODE` | no | no | required in future setup | planned | Future values: `interactive`, `non_interactive`, or `disabled`. |
| Disable setup after bootstrap | none | `SATOIDC_DISABLE_SETUP_AFTER_BOOTSTRAP` | no | no | required in future setup | planned | Future public setup lock after completion. |
| UI theme | none | `SATOIDC_THEME` | no | no | optional | planned | Future wizard-owned UI setting. |
| Log level | none | `SATOIDC_LOG_LEVEL` | no | no | optional | planned | Future observability setting; no current runtime support. |
| Basic rate-limit note | none | `SATOIDC_BASIC_RATE_LIMIT` | no | no | optional | planned | Documentation-only hint when rate limiting is delegated to the proxy. |

## Future Setup Wizard Interface

`specs/features/setup-wizard/spec.md` defines the preferred future
operator-facing environment variable namespace with `SATOIDC_*` names, including
`SATOIDC_PUBLIC_BASE_URL`, `SATOIDC_ISSUER`, `SATOIDC_DATABASE_URL`,
`SATOIDC_SECRET_KEY`, and bootstrap admin variables.

This contract keeps current names authoritative for today's runtime and defines
the future alias behavior required before the Setup Wizard can depend on
`SATOIDC_*` inputs. Documentation for operators must clearly label planned
aliases until runtime support and settings tests exist.

Wizard-owned mutable settings are defined separately in
[docs/setup-wizard-mutable-settings.md](../../docs/setup-wizard-mutable-settings.md).
Persisted database configuration may participate in runtime resolution only
after environment and `_FILE` sources have been checked, and only for logical
settings that document explicitly marks as wizard-owned.

## Database Configuration

SatOIDC must keep first-class support for both SQLite and PostgreSQL.

- SQLite defaults are used when no `.env` is present.
- PostgreSQL is configured by setting both `DATABASE_URL` and
  `SYNC_DATABASE_URL` to PostgreSQL URLs for the same database.
- The app must not mix SQLite for async routes with PostgreSQL for Authlib, or
  the inverse.
- Startup settings validate that `DATABASE_URL` and `SYNC_DATABASE_URL` target
  the same backend and database before engines are created.
- Production documentation should present PostgreSQL as the recommended
  database, while preserving SQLite as a supported local/simple deployment
  option.

## Signing Backend Configuration

SatOIDC must be usable with or without OpenBao.

- Without OpenBao, SatOIDC uses its internal OIDC key lifecycle and encrypted
  database-backed private JWK storage.
- `OIDC_SIGNING_BACKEND=database` preserves the internal encrypted
  database-backed signer.
- `OIDC_SIGNING_BACKEND=transit` uses a Vault-compatible Transit API. SatOIDC
  creates or rotates an RSA 2048 Transit key, exports the public key for JWKS,
  stores the backend key reference/version in signing metadata, and sends only
  JWT signing input to Transit.
- OpenBao support is a production-hardening capability, not a prerequisite for
  running the app locally.

Risk warning for internal signing:

- The internal mechanism protects private key material from accidental exposure,
  but it still depends on the database and runtime secret remaining separated.
- If an attacker compromises both the database and the runtime secret used to
  encrypt private JWKs, they can compromise OIDC signing and potentially forge
  tokens.
- Hardened production deployments should prefer OpenBao Transit or another
  external signing backend when the threat model includes database compromise,
  privileged host access, or multiple operators.

## FastAPI App Configuration

`satoidc/satoidc/main.py` creates `FastAPI(title="Identity Service",
version="0.1.0")`.

Middleware order:

1. `AuthMiddleware`
2. Starlette `SessionMiddleware`

Session middleware settings:

- `same_site="lax"`
- `https_only=ENV.session_cookie_https_only`
- `session_cookie="client_session"`

Production behavior:

- Production mode rejects placeholder session/JWT secrets.
- Production mode rejects missing or local-development OIDC issuer values.
- Production mode requires HTTPS-only session cookies.
- Production mode rejects mismatched async/sync database URLs.
- If production starts with placeholder generated-owned secrets and
  `SETUP_GENERATED_SECRETS_PATH` is an absolute path, bootstrap writes an
  idempotent shell env file and the container entrypoint sources it before
  importing the application.

## OAuth App Configuration

The app sets:

- `OAUTH2_JWT_ISS`
- `OAUTH2_JWT_KEY`
- `OAUTH2_JWT_ALG`
- `OAUTH2_TOKEN_EXPIRES_IN`
- `OAUTH2_REFRESH_TOKEN_GENERATOR=True`
- one `invalid_client` error URI under `developer.<DOMAIN>`

Authlib is configured through `config_oauth(app)`.

## NiceGUI Configuration

- `apply_theme()` is called before mounting NiceGUI.
- `ui.run_with(app, title="SatOIDC - Identity Service")` attaches NiceGUI to
  the FastAPI app.

## Acceptance Criteria

- Given no `.env`, when the app imports settings, then SQLite development
  defaults are used.
- Given Compose environment variables, when the container starts, then the app
  uses PostgreSQL URLs and the configured issuer/session secret.
- Given no OpenBao configuration is present, when the app starts in development,
  then internal database-backed signing remains available.
- Given hardened production mode uses a Transit backend, when SatOIDC signs an
  ID Token, then private key material does not leave OpenBao or the compatible
  Transit backend.
- Given the app starts, then Authlib is configured before routers handle OAuth
  endpoints.
- Given the UI starts, then the global NiceGUI theme is applied before page
  rendering.
