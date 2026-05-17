# Runtime Configuration Contract

Status: draft
Area: Runtime/Configuration
Last Updated: 2026-05-17

## Intent

Describe the current settings, defaults, and startup configuration used by the
SatOIDC FastAPI/NiceGUI application.

## Settings Source

Runtime settings are loaded by `satoidc/satoidc/settings.py` using Pydantic
settings.

The app reads `.env` from the current working directory with UTF-8 encoding.

## Settings

| Setting | Default | Purpose |
| --- | --- | --- |
| `SERVICE_NAME` | `SatOIDC` | Human-readable service name. |
| `DOMAIN` | empty string | Used when building OAuth error URI hostnames. |
| `APP_ENV` | `development` | Runtime environment; `production` and `prod` enable production checks. |
| `DATABASE_URL` | `sqlite+aiosqlite:///satoidc.db` | Async SQLAlchemy URL. |
| `SYNC_DATABASE_URL` | `sqlite:///satoidc.db` | Sync SQLAlchemy URL for Authlib. |
| `LNURL_K1_TTL_SECONDS` | `60` | LNURL challenge lifetime and QR refresh cadence. |
| `OAUTH2_JWT_ISS` | `http://localhost:8000` | OIDC issuer and endpoint base. |
| `OAUTH2_JWT_AUDIENCE` | `SatOIDC-clients` | Configured audience value. |
| `OAUTH2_JWT_SECRET_KEY` | `CHANGE_ME_TO_A_LONG_RANDOM_SECRET` | Configured but current ID token signing uses generated RSA key material. |
| `OAUTH2_JWT_ALG` | `RS256` | ID token signing algorithm advertised and used. |
| `OAUTH2_TOKEN_EXPIRES_IN` | `300` | Authorization-code token expiration value. |
| `OIDC_SIGNING_BACKEND` | `database` | OIDC signing backend selector; supported values are `database` and `transit`. |
| `SESSION_MIDDLEWARE_SECRET_KEY` | `CHANGE_ME_TO_A_LONG_RANDOM_SECRET` | Starlette session signing secret. |
| `SESSION_COOKIE_HTTPS_ONLY` | unset | Optional explicit secure-cookie override; defaults to enabled in production and disabled in development. |
| `SETUP_GENERATED_SECRETS_PATH` | unset | Optional absolute shell env file path where bootstrap can persist generated-owned secrets before app startup. |

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
- `OIDC_SIGNING_BACKEND=transit` is reserved for the Vault-compatible Transit
  backend and currently fails closed until the Transit client is implemented.
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
