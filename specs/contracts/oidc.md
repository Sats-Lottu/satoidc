# OIDC Contract

Status: draft
Updated: 2026-05-06

## Endpoints

Current implementation exposes canonical OIDC metadata under:

- `GET /.well-known/openid-configuration`

Current metadata points to:

- `authorization_endpoint`: `<issuer>/authorize`
- `token_endpoint`: `<issuer>/oauth/token`
- `userinfo_endpoint`: `<issuer>/oauth/userinfo`
- `jwks_uri`: `<issuer>/.well-known/jwks.json`

## Supported Values

- `response_types_supported`: `["code"]`
- `grant_types_supported`: `["authorization_code", "refresh_token"]`
- `subject_types_supported`: `["public"]`
- `id_token_signing_alg_values_supported`: `["RS256"]`
- `scopes_supported`: `openid`, `profile`, `email`
- `token_endpoint_auth_methods_supported`: `none`, `client_secret_post`, `client_secret_basic`
- `code_challenge_methods_supported`: `S256`

## UserInfo Claims

- `sub`: user UUID as string.
- `email`: included when `email` scope is granted.
- `name`: included when `profile` scope is granted.
- `lnurl_pubkey`: included when `profile` scope is granted.

## Open Questions

- Should JWKS come from persistent configured key material instead of process memory?
