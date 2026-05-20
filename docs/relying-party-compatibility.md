# Relying-Party Compatibility Matrix

This matrix records practical OIDC relying-party compatibility for SatOIDC.
Only entries marked `verified` have repository-backed evidence. Entries marked
`pending` are configuration targets, not support claims.

## Current Verified Integrations

| Client | Status | Auth method | Redirect behavior | Scopes | Token/UserInfo expectations | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Authlib Starlette confidential client | verified | `client_secret_post` | Exact registered callback URI | `openid email profile` | Authorization code exchange returns access token, refresh token, and ID Token; UserInfo returns `sub`, `email`, `name`, and profile claims when scoped. | `tests/e2e/test_oauth_authorization_code_e2e.py`; `examples/basic_client.py` |
| Public browser client with PKCE | verified | `none` with `S256` PKCE | Exact registered callback URI | `openid email profile` | Authorization code exchange requires verifier and returns access token, refresh token, and ID Token; UserInfo succeeds with `profile`. | `tests/e2e/test_oauth_authorization_code_e2e.py`; `examples/public_client.py` |

## Planned Compatibility Targets

| Client | Status | Expected auth method | Redirect notes | Scope notes | Limitations to verify |
| --- | --- | --- | --- | --- | --- |
| Grafana Generic OAuth | pending | `client_secret_post` or `client_secret_basic` | Requires exact root URL callback from Grafana config. | Usually `openid email profile`. | Verify role mapping behavior and whether `email_verified` is required. |
| oauth2-proxy OIDC provider | pending | `client_secret_post` or `client_secret_basic` | Requires external HTTPS issuer and callback URL. | Usually `openid email profile`. | Verify cookie/session behavior and reverse-proxy headers. |
| Gitea OpenID Connect | pending | `client_secret_post` or `client_secret_basic` | Requires Gitea OAuth2 callback URL. | Usually `openid email profile`. | Verify username/email claim mapping. |
| MinIO OpenID | pending | `client_secret_post` | Requires console callback URL and policy claim planning. | `openid profile email`; policy claims are not currently SatOIDC-specific. | Verify claim mapping and policy expectations before documenting support. |
| Auth.js / NextAuth.js | pending | `client_secret_post` for server-side app; public PKCE depends on app shape. | Requires HTTPS callback in production. | `openid email profile`. | Verify JWKS/ID Token validation and refresh behavior. |

## Configuration Requirements

All relying parties must match SatOIDC's advertised contract:

- Discovery: `/.well-known/openid-configuration`
- Authorization endpoint: `/authorize`
- Token endpoint: `/oauth/token`
- UserInfo endpoint: `/oauth/userinfo`
- JWKS endpoint: `/.well-known/jwks.json`
- Response type: `code`
- Supported grant types: `authorization_code`, `refresh_token`
- Supported token endpoint auth methods: `none`, `client_secret_post`,
  `client_secret_basic`
- Supported PKCE method: `S256`
- Supported scopes: `openid`, `email`, `profile`

Redirect URIs must match the registered client metadata exactly.

## Verification Checklist

For each new relying party, record:

- client software and version;
- SatOIDC commit SHA;
- auth method;
- redirect URI;
- requested scopes;
- whether login, token exchange, ID Token validation, refresh, and UserInfo
  passed;
- any claim mapping limitations;
- whether HTTPS/reverse-proxy headers were involved.

Do not mark a relying party as `verified` from configuration review alone.
