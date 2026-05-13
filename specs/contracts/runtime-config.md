# Runtime Configuration Contract

Status: draft
Area: Runtime/Configuration
Last Updated: 2026-05-13

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
| `DATABASE_URL` | `sqlite+aiosqlite:///satoidc.db` | Async SQLAlchemy URL. |
| `SYNC_DATABASE_URL` | `sqlite:///satoidc.db` | Sync SQLAlchemy URL for Authlib. |
| `LNURL_K1_TTL_SECONDS` | `60` | LNURL challenge lifetime and QR refresh cadence. |
| `OAUTH2_JWT_ISS` | `http://localhost:8000` | OIDC issuer and endpoint base. |
| `OAUTH2_JWT_AUDIENCE` | `SatOIDC-clients` | Configured audience value. |
| `OAUTH2_JWT_SECRET_KEY` | `CHANGE_ME_TO_A_LONG_RANDOM_SECRET` | Configured but current ID token signing uses generated RSA key material. |
| `OAUTH2_JWT_ALG` | `RS256` | ID token signing algorithm advertised and used. |
| `OAUTH2_TOKEN_EXPIRES_IN` | `300` | Authorization-code token expiration value. |
| `SESSION_MIDDLEWARE_SECRET_KEY` | `CHANGE_ME_TO_A_LONG_RANDOM_SECRET` | Starlette session signing secret. |

## FastAPI App Configuration

`satoidc/satoidc/__init__.py` creates `FastAPI(title="Identity Service",
version="0.1.0")`.

Middleware order:

1. `AuthMiddleware`
2. Starlette `SessionMiddleware`

Session middleware settings:

- `same_site="lax"`
- `https_only=False`
- `session_cookie="client_session"`

Current production caveat:

- `https_only=False` is development-oriented and should become
  production-aware before deployment behind HTTPS.

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
- Given the app starts, then Authlib is configured before routers handle OAuth
  endpoints.
- Given the UI starts, then the global NiceGUI theme is applied before page
  rendering.
