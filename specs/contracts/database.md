# Database Contract

Status: draft
Area: Persistence
Last Updated: 2026-05-13

## Intent

Describe the current SatOIDC persistence model and the session boundaries used
by FastAPI routes and Authlib helpers.

## Session Boundaries

- FastAPI routes use async SQLAlchemy sessions from `get_session()`.
- Authlib SQLAlchemy helpers use a separate synchronous scoped session named
  `db`.
- `DATABASE_URL` and `SYNC_DATABASE_URL` must point to the same database.
- OAuth routes that call Authlib from async request handlers run synchronous
  Authlib work in a threadpool and call `remove_sync_session()` afterward.

## Tables

### `users`

Fields:

- `id`: UUID primary key.
- `lnurl_pubkey`: unique nullable public key from LNURL-auth.
- `email`: unique nullable email.
- `login`: unique nullable login.
- `password_hash`: nullable password hash.
- `nickname`: non-null display name, default `Satoshi`.
- `is_active`: boolean, default `true`.
- `created_at`: database timestamp.
- `updated_at`: database timestamp updated on mutation.

Relationships:

- `permissions`: permissions assigned to this user.
- `granted_permissions`: permissions granted by this user.

### `permissions`

Fields:

- `id`: integer primary key.
- `user_id`: user receiving the permission.
- `granted_by`: optional user who granted it.
- `permission_type`: `PermissionsEnum`.
- `expiration_date`: nullable timestamp.
- `reason`: nullable text.
- `disabled`: boolean, default `false`.
- `created_at`: database timestamp.

Constraints:

- Unique `(user_id, permission_type)`.

Current permission enum values:

- `root`
- `admin`
- `support`

Current UI also checks for the string permission `developer`; this is a known
taxonomy gap and is covered by `specs/features/permission-requests/spec.md`.

### `lnurl_auth_challenges`

Fields:

- `k1`: primary key, generated from 32 random bytes encoded as hex.
- `user_id`: optional user linked to the challenge.
- `action`: conventionally `login`, `register`, `link`, or `auth`.
- `verified`: replay guard.
- `created_at`: database timestamp.
- `updated_at`: database timestamp updated on mutation.

### OAuth2 Tables

Authlib SQLAlchemy mixins define:

- `oauth2_client`
- `oauth2_code`
- `oauth2_token`

Current local behavior:

- `OAuth2Client.user_id` references `users.id`.
- `OAuth2AuthorizationCode.user_id` references `users.id`.
- `OAuth2AuthorizationCode.is_expired()` returns true after 300 seconds.
- `OAuth2Token.user_id` references `users.id`.
- `OAuth2Token.is_refresh_token_active()` accepts refresh tokens until
  `issued_at + expires_in * 2` unless revoked.

## Migration Baseline

Current migration baseline:

- `satoidc/migrations/versions/32a836ab058b_create_initial_tables.py`

Future schema changes must add migrations rather than rewriting the baseline.

## Acceptance Criteria

- Given async route code, when it needs database access, then it uses
  `get_session()`.
- Given Authlib helper code, when it queries clients/tokens/codes, then it uses
  the sync scoped session.
- Given OAuth route threadpool work completes, then the sync scoped session is
  removed.
- Given tests create a real database, then user, permission, LNURL challenge,
  OAuth client, authorization code, and token records can persist.
