# OAuth Token Lifecycle Flow

Status: draft
Area: OAuth/OIDC
Last Updated: 2026-05-17

## Intent

Describe the current token issuance, refresh, introspection, revocation, and
UserInfo behavior.

## Authorization Code Token Exchange

1. Client posts to `/oauth/token`.
2. Route caches the request body for the synchronous adapter.
3. Route delegates to Authlib in a threadpool.
4. Authlib authenticates the client using registered methods:
   - `client_secret_basic`
   - `client_secret_post`
   - `none`
5. Authlib validates authorization code, redirect URI, PKCE challenge, and
   client metadata.
6. Authlib stores an `OAuth2Token`.
7. OpenID Connect support issues an ID token when applicable.
8. The used authorization code is deleted.

## Refresh Token Grant

1. Client posts a refresh token to `/oauth/token`.
2. `RefreshTokenGrant` loads the stored token by refresh token value.
3. The refresh token is active only when:
   - it is not revoked, and
   - `issued_at + expires_in * 2` is still in the future.
4. The grant authenticates the token's user.
5. A new refresh token is included.
6. The old refresh token is marked revoked by setting
   `refresh_token_revoked_at`.

## Introspection

Endpoint:

- `POST /oauth/introspect`

Current behavior:

- Supports `access_token` hint.
- Supports `refresh_token` hint.
- Falls back to access-token lookup then refresh-token lookup.
- Checks that the token belongs to the introspecting client.
- Returns active token claims including:
  - `active`
  - `client_id`
  - `token_type`
  - `username`
  - `scope`
  - `sub`
  - `aud`
  - `iss`
  - `exp`
  - `iat`

## Revocation

Endpoint:

- `POST /oauth/revoke`

Current behavior is provided by Authlib's SQLAlchemy revocation endpoint for
`OAuth2Token`.

## UserInfo

Endpoint:

- `GET /oauth/userinfo`

Current behavior:

- Protected by bearer token resource protection requiring `["profile"]`.
- Always returns `sub`.
- Includes `email` when token scope contains `email`.
- Includes `name` and `lnurl_pubkey` when token scope contains `profile`.

## Signing Key

Current ID token/JWKS key material:

- Stored in the `oidc_signing_keys` table with encrypted private JWK material.
- RSA 2048 private key with persisted `kid`.
- Active keys sign new ID tokens.
- Validating and retired keys remain available through JWKS while needed for
  token verification.
- Key lifecycle actions are recorded in `oidc_signing_key_audit_events`.
- Public keys are exposed at `/.well-known/jwks.json`.

The production hardening question that remains is whether signing should move
from database-encrypted private JWK storage to Vault Transit or another
external signing backend.

## Acceptance Criteria

- Given a valid authorization code and PKCE verifier, when token exchange runs,
  then Authlib issues tokens and deletes the code.
- Given an active refresh token, when refresh grant runs, then a new refresh
  token is issued and the old one is revoked.
- Given a revoked refresh token, when refresh grant runs, then it is rejected.
- Given an access token introspection request from the owning client, then
  active token metadata is returned.
- Given UserInfo is called with a token lacking `profile`, then resource
  protection rejects the call.
- Given UserInfo is called with `email profile`, then `sub`, `email`, `name`,
  and `lnurl_pubkey` are derived from the token user.
- Given a public PKCE or confidential `client_secret_post` browser flow
  completes, then the authorization code is exchanged for tokens and UserInfo
  succeeds with the issued access token.
- Given the integration load smoke runs with Docker available, then concurrent
  PostgreSQL-backed authorization-code token exchanges complete without token
  endpoint errors.
