---
title: Risks And Pitfalls
tags:
  - agent-memory/state
  - agent-memory/todo
type: state
project: satoidc
status: active
updated: 2026-05-16
---

# Risks And Pitfalls

High priority:

- OIDC signing keys now persist encrypted in the database, but production hardening should still evaluate Vault Transit or another external cryptographic backend.
- `AuthMiddleware` currently uses broad public-prefix matching. Harden it with segment-boundary-aware matching before adding protected routes that share names with public prefixes.

Medium priority:
- LNURL callback intentionally consumes a challenge before signature validation as a replay-defense measure, including invalid signatures. The model field is now named `consumed` to avoid implying successful signature verification.
- LNURL registration can create a user with nullable identity fields and `nickname=None` despite non-null model expectation.
- Refresh grant has focused unit/integration tests, but still needs broader end-to-end client-flow coverage.
- Keep an eye on README/examples encoding when editing from non-UTF-8 shell sessions.
- Prefer a Vault-compatible external signing boundary for hardened production. OpenBao is the better philosophical/default self-hosted fit; HashiCorp Vault remains a compatibility target for managed/vendor-supported environments.
- NiceGUI route files still contain persistence-heavy actions that should be extracted gradually into service/use-case helpers.
- Add sanitized operational logging for auth, OIDC, LNURL, and UI mutation failures before production hardening.

Resolved/reduced on 2026-05-08:

- Password registration is separated into `POST /register` and now sanitizes redirects, validates server-side, rejects duplicates, creates the user, and logs the user in.
- Default unit/integration coverage reached 100%; visual NiceGUI rendering remains covered by Playwright smoke tests.

Resolved/reduced on 2026-05-13:

- Authenticated UI e2e tests have been added for home/profile, developer dashboard states, and create-client validation/success.
- Full browser OAuth authorization-code e2e tests now cover public PKCE and confidential `client_secret_post` clients through login, consent, redirect, token exchange, ID Token, refresh token issuance, and UserInfo.
- Password login and LNURL redirect now sanitize `redirect_to`.
- OIDC signing key rotation is implemented with persistent encrypted key material, stable JWKS `kid`, key retention windows, admin endpoints, and audit events.
- Permission names are normalized around `root`, `admin`, `developer`, and `support`; developer access requests persist, admin approval grants `developer`, and admin dashboard operational counts are database-backed.

Resolved/reduced on 2026-05-15:

- Priority execution backlog items 1-12 are implemented and documented.
- OAuth browser e2e now covers public PKCE and confidential `client_secret_post` paths with real redirects, token exchange, ID Token, refresh token issuance, and UserInfo.
- Authenticated UI e2e now covers home/profile, wallet-link QR rendering, developer dashboard empty/populated states, create-client validation/success, and admin approval of a pending developer request.
- OAuth adapter preserves the `Authorization` header case expected by Authlib's bearer token validator.
- UserInfo scope acquisition now passes a scope list to Authlib, matching the validator API.
- Password login preserves OAuth redirect query strings without HTML entity corruption in hidden form values.
