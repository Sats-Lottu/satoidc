# Setup Wizard Mutable Settings

Updated: 2026-05-22

This document defines which SatOIDC settings the Setup Wizard may persist and
mutate after initial bootstrap. It exists to close the product decision behind
Task 3.7 without making environment-controlled deployments unsafe.

Related specs:

- [Setup Wizard Complete Specification](../specs/features/setup-wizard/spec.md)
- [Runtime Configuration Contract](../specs/contracts/runtime-config.md)

## Ownership Rule

The Setup Wizard may persist only settings that are:

- non-secret, or represented by a secret reference rather than the secret value;
- safe to change from an authenticated root/admin UI;
- not explicitly configured by process environment variables or `_FILE` inputs;
- validated before storage and applied only through the normal runtime
  configuration resolver.

Environment values always win. If `SATOIDC_*`, current env names, or supported
`*_FILE` variables are set for a logical setting, the wizard must render that
setting as locked/read-only and must not persist an overriding value.

## Persistence Model

Implement wizard-owned settings in a dedicated database table rather than in
`setup_state`. `setup_state` remains the lifecycle/lock record for setup
completion and concurrent apply protection.

Recommended table:

```text
setup_runtime_settings
```

Recommended columns:

| Column | Purpose |
| --- | --- |
| `key` | Stable logical setting key, unique, lowercase snake case. |
| `value` | JSON value for non-secret settings. |
| `secret_ref` | Optional external secret reference for future secret-backed fields. |
| `source` | `wizard`, `setup`, `admin_reconfigure`, or future migration source. |
| `updated_by` | User id or system actor string. |
| `updated_at` | Timestamp for last mutation. |
| `version` | Integer schema/version marker for value interpretation. |

Do not store raw SMTP passwords, app secrets, Transit tokens, database
passwords, private JWKs, OAuth client secrets, or root/admin passwords in this
table.

## Runtime Precedence

The runtime resolver should use this order:

1. Explicit `Settings(...)` values used by tests/internal callers.
2. `SATOIDC_*` direct environment variables.
3. Supported `SATOIDC_*_FILE` values.
4. Current direct environment variables.
5. Supported current `*_FILE` values.
6. Wizard-owned persisted settings from `setup_runtime_settings`.
7. Safe defaults from `settings.py`.

The wizard UI writes step 6 only. It cannot write values that would outrank
environment configuration.

## Mutable Settings For First Implementation

These settings are reasonable for the first persisted wizard-owned set because
they are already represented in runtime settings or documented setup behavior
and are safe to edit from an authenticated admin UI when env is absent.

| Logical key | Runtime/env mapping | Value type | Validation | Restart required | Notes |
| --- | --- | --- | --- | --- | --- |
| `instance_name` | `SERVICE_NAME` / `SATOIDC_INSTANCE_NAME` | string | 1-80 visible chars | yes | Display/product label only. |
| `public_base_url` | `EMAIL_PUBLIC_BASE_URL` / `SATOIDC_PUBLIC_BASE_URL` | absolute URL | HTTP(S); HTTPS and non-local in production | yes | Drives email links and future public URL checks. |
| `issuer` | `OAUTH2_JWT_ISS` / `SATOIDC_ISSUER` | absolute URL | HTTP(S); HTTPS/non-local in production; no query/fragment | yes | High impact. Changing it can invalidate relying-party metadata assumptions. |
| `session_cookie_https_only` | `SESSION_COOKIE_HTTPS_ONLY` / `SATOIDC_SESSION_COOKIE_HTTPS_ONLY` | boolean or null | true required in production | yes | Null means derive from `APP_ENV`. |
| `lnurl_k1_ttl_seconds` | `LNURL_K1_TTL_SECONDS` / `SATOIDC_LNURL_K1_TTL_SECONDS` | integer | 30-600 | yes | Challenge/QR lifetime. |
| `oidc_audience` | `OAUTH2_JWT_AUDIENCE` / `SATOIDC_OIDC_AUDIENCE` | string | non-empty, no control chars | yes | Keep conservative until conformance evidence exists. |
| `token_lifetime_seconds` | `OAUTH2_TOKEN_EXPIRES_IN` / `SATOIDC_TOKEN_LIFETIME_SECONDS` | integer | 60-86400 | yes | High impact for token behavior and key retention. |
| `jwks_cache_ttl_seconds` | `OIDC_JWKS_CACHE_TTL_SECONDS` / `SATOIDC_OIDC_JWKS_CACHE_TTL_SECONDS` | integer | 0-86400 | yes | Coordinate with key rotation windows. |
| `key_retention_margin_seconds` | `OIDC_KEY_RETENTION_MARGIN_SECONDS` / `SATOIDC_OIDC_KEY_RETENTION_MARGIN_SECONDS` | integer | >= token lifetime safety margin | yes | Prevent retiring validating keys too early. |
| `email_sender_mode` | `EMAIL_SENDER_MODE` / `SATOIDC_EMAIL_SENDER_MODE` | enum | `disabled`, `console`, `smtp` | yes | SMTP mode requires SMTP host. |
| `email_sender` | `SMTP_FROM_EMAIL` / `SATOIDC_EMAIL_SENDER` | email string | valid email address | yes | Sender identity for verification/recovery mail. |
| `email_verification_token_ttl_seconds` | `EMAIL_VERIFICATION_TOKEN_TTL_SECONDS` / `SATOIDC_EMAIL_VERIFICATION_TOKEN_TTL_SECONDS` | integer | 300-604800 | yes | Current tokens keep their creation-time expiry. |
| `email_reset_token_ttl_seconds` | `EMAIL_RESET_TOKEN_TTL_SECONDS` / `SATOIDC_EMAIL_RESET_TOKEN_TTL_SECONDS` | integer | 300-86400 | yes | Keep shorter than verification TTL. |
| `email_token_min_request_interval_seconds` | `EMAIL_TOKEN_MIN_REQUEST_INTERVAL_SECONDS` / `SATOIDC_EMAIL_TOKEN_MIN_REQUEST_INTERVAL_SECONDS` | integer | 0-86400 | yes | In-app resend/request interval, separate from reverse proxy throttling. |
| `smtp_host` | `SMTP_HOST` / `SATOIDC_SMTP_HOST` | hostname | required when SMTP mode is `smtp` | yes | Non-secret. |
| `smtp_port` | `SMTP_PORT` / `SATOIDC_SMTP_PORT` | integer | 1-65535 | yes | Usually 465 or 587. |
| `smtp_username` | `SMTP_USERNAME` / `SATOIDC_SMTP_USERNAME` | string | optional, no control chars | yes | Treat as sensitive in UI even if not a secret. |
| `smtp_use_tls` | `SMTP_USE_TLS` / `SATOIDC_SMTP_TLS` | boolean | not both implicit TLS and invalid port warning | yes | Existing runtime flag. |
| `smtp_start_tls` | `SMTP_START_TLS` / `SATOIDC_SMTP_STARTTLS` | boolean | coherent with `smtp_use_tls` | yes | Existing runtime flag. |
| `oidc_signing_backend` | `OIDC_SIGNING_BACKEND` / `SATOIDC_OIDC_SIGNING_BACKEND` | enum | `database`, `transit` | yes | High impact. Transit requires complete Transit settings. |
| `oidc_transit_addr` | `OIDC_TRANSIT_ADDR` / `SATOIDC_OIDC_TRANSIT_ADDR` | absolute URL | required when backend is `transit` | yes | Do not persist token value with this. |
| `oidc_transit_mount` | `OIDC_TRANSIT_MOUNT` / `SATOIDC_OIDC_TRANSIT_MOUNT` | string | non-empty path segment | yes | Defaults to `transit`. |
| `oidc_transit_key_name` | `OIDC_TRANSIT_KEY_NAME` / `SATOIDC_OIDC_TRANSIT_KEY_NAME` | string | non-empty safe key name | yes | Existing runtime setting. |

## Mutable Later, Not First

These settings are useful product controls, but they should not be persisted
until runtime support and tests exist.

| Logical key | Reason to defer |
| --- | --- |
| `lnurl_auth_enabled` | No current runtime switch exists. |
| `default_oidc_scopes` | Scope defaults are not a standalone runtime policy yet. |
| `refresh_token_lifetime_seconds` | No current setting; refresh behavior needs a dedicated token lifecycle spec update. |
| `require_pkce` | PKCE policy is protocol-sensitive and currently enforced by client/type behavior. |
| `redirect_uri_policy` | Redirect validation policy needs a separate security contract before becoming mutable. |
| `jwk_rotation_policy` | Current key lifecycle exists, but rotation policy UI needs a dedicated safety design. |
| `theme` | No durable app-level theme setting exists; user/browser theme remains UI-level behavior. |
| `log_level` | Logging baseline is still draft; changing it dynamically needs observability design. |
| `basic_rate_limit` | Rate limiting is delegated to the reverse proxy; keep this as documentation/checklist only. |

## Never Wizard-Owned

These settings must remain environment/deployment-controlled or handled by a
specialized feature flow:

| Setting | Reason |
| --- | --- |
| `DATABASE_URL`, `SYNC_DATABASE_URL` | Database moves need deployment planning, migrations, backup/restore, and service restart. The wizard may display diagnostics only. |
| `SESSION_MIDDLEWARE_SECRET_KEY`, `OAUTH2_JWT_SECRET_KEY` | Secret rotation affects sessions and encrypted OIDC key material; requires a dedicated rotation procedure. |
| `OIDC_TRANSIT_TOKEN`, `SMTP_PASSWORD` | Persist only through `_FILE` or a future secret-store reference, never as raw wizard-owned DB values. |
| `APP_ENV` | Determines production safety behavior and must be deployment-owned. |
| `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, `SATOIDC_PORT` | Compose/container concerns, not Python runtime wizard settings. |
| `SATOIDC_ADMIN_USERNAME`, `SATOIDC_ADMIN_EMAIL`, `SATOIDC_ADMIN_PASSWORD` | Bootstrap inputs only. After setup, admin identity changes use user/profile/admin flows. |
| OAuth client secrets | Managed by OAuth client creation/rotation flows with one-time display. |
| OIDC private keys | Managed by the OIDC key lifecycle and signing backend. |

## Reconfiguration UI Behavior

The admin reconfiguration UI should group settings as:

- `Mutable in wizard`: editable when no env value controls the setting.
- `Locked by environment`: read-only with the controlling env var or `_FILE`
  source name.
- `Deployment-owned`: read-only diagnostics with guidance to update Compose,
  secrets, database, or reverse proxy configuration.
- `Unsupported yet`: visible only as roadmap/spec context, not editable.

High-impact mutable settings must require explicit confirmation before apply:

- `public_base_url`
- `issuer`
- `token_lifetime_seconds`
- `key_retention_margin_seconds`
- `oidc_signing_backend`
- Transit settings
- SMTP mode when switching into or out of `smtp`

## Implementation Checklist

- Add `setup_runtime_settings` model and Alembic migration.
- Add a settings repository/service that reads/writes typed values.
- Extend runtime settings resolution to load persisted values after env and
  before defaults.
- Add validators for each first-implementation mutable setting.
- Update setup apply/reconfiguration flows to persist only unlocked settings.
- Log/audit setting changes without secret values.
- Add unit tests for precedence, locked env behavior, validation, masking, and
  high-impact confirmation.
- Add e2e coverage for admin reconfiguration editing one safe setting and
  showing env-controlled fields as locked.
