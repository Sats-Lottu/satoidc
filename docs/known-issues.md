# Known Issues And Technical Debt

Updated: 2026-05-06

## High Priority

1. `login_post` does not sanitize `redirect_to` with `safe_redirect`, unlike registration.
2. JWT signing key is generated in memory at startup, making JWKS unstable across restarts and replicas.
3. OIDC signing key rotation is specified but not implemented; production still needs persistent key material, `kid` handling, retention windows, admin authorization and audit events.
4. Full browser OAuth authorization-code e2e coverage is still partial; current e2e tests are public-page and endpoint smoke/responsive checks.

## Medium Priority

1. Permission taxonomy is inconsistent between enum, migration, dashboard, profile checks, and intended developer access.
2. LNURL challenge is consumed before signature verification succeeds.
3. LNURL registration can create `User(nickname=None)` even though `nickname` is non-nullable.
4. Refresh token support has focused tests, but still needs broader end-to-end client-flow coverage.
5. README and examples may show mojibake in some shell sessions.

## Lower Priority

1. `dashboard.py` includes placeholder menu item `asdf`.
2. Several profile actions are placeholders.
3. Client creation lacks strong validation and permission decorator.
4. Production cookie and HTTPS settings need hardening.
5. Keep new Markdown discoverable from `README.md`, `docs/README.md`, `specs/index.md`, or `agent-memory/index.md` to avoid orphan docs.

## Suggested First Specs

- `login-redirect-safety`
- `oidc-key-rotation` is drafted in `specs/features/oidc-key-rotation/`; implementation is still pending.
- `permissions-model`
- `lnurl-challenge-lifecycle`
- `oidc-discovery-contract`
