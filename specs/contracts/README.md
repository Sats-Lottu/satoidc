# Contracts

Use this folder for contracts that must stay stable across features.

Good candidates in SatOIDC:

- OAuth2 and OIDC endpoints.
- ID token and JWKS shape.
- UserInfo response.
- LNURL-auth callback parameters.
- Database model expectations.
- Client metadata shape.

Contracts should be precise enough to generate or validate tests from them.

## Current Contracts

- [Authlib FastAPI Adapter](authlib-adapter.md): request and resource-protector adapter behavior for Authlib.
- [Database Contract](database.md): models, session boundaries, and migration baseline.
- [OIDC Contract](oidc.md): discovery, JWKS, token, UserInfo, introspection, and revocation expectations.
- [Runtime Configuration Contract](runtime-config.md): settings, middleware, OAuth app config, and NiceGUI startup.
- [Security And Session Contract](security-session.md): public paths, sessions, page permissions, passwords, redirects, and flow nonces.

Keep this list aligned with [../index.md](../index.md).
