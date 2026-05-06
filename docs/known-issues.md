# Known Issues And Technical Debt

Updated: 2026-05-06

## High Priority

1. No meaningful tests exist. `poetry run task test` collects zero tests and exits with failure.
2. `login_post` does not sanitize `redirect_to` with `safe_redirect`, unlike registration.
3. JWT signing key is generated in memory at startup, making JWKS unstable across restarts and replicas.
4. `ResourceProtector.acquire_token` likely calls `FastAPIOAuth2Request` with the wrong signature.

## Medium Priority

1. Permission taxonomy is inconsistent between enum, migration, dashboard, profile checks, and intended developer access.
2. LNURL challenge is consumed before signature verification succeeds.
3. LNURL registration can create `User(nickname=None)` even though `nickname` is non-nullable.
4. Refresh token support is registered but token generation may not issue refresh tokens by default.
5. OIDC docs mention both RS256 and ES256.
6. README and examples show mojibake in this shell session.

## Lower Priority

1. `dashboard.py` includes placeholder menu item `asdf`.
2. Several profile actions are placeholders.
3. Client creation lacks strong validation and permission decorator.
4. Production cookie and HTTPS settings need hardening.

## Suggested First Specs

- `login-redirect-safety`
- `persistent-jwks-and-key-rotation`
- `permissions-model`
- `lnurl-challenge-lifecycle`
- `oidc-discovery-contract`
