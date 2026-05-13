---
title: Risks And Pitfalls
tags:
  - agent-memory/state
  - agent-memory/todo
type: state
project: satoidc
status: active
updated: 2026-05-13
---

# Risks And Pitfalls

High priority:

- Full browser OAuth authorization-code e2e coverage is still incomplete; current Playwright tests cover public pages, responsiveness, and well-known endpoint smoke behavior.
- OIDC signing keys now persist encrypted in the database, but production hardening should still evaluate Vault Transit or another external cryptographic backend.

Medium priority:

- Permission names are inconsistent: enum has `root`, `admin`, `support`; migration includes `DRAW_OPERATOR`; UI checks use `developer`, `admin`, `root`.
- LNURL callback intentionally consumes a challenge before signature validation as a replay-defense measure, including invalid signatures. The model field is now named `consumed` to avoid implying successful signature verification.
- LNURL registration can create a user with nullable identity fields and `nickname=None` despite non-null model expectation.
- Refresh grant has focused unit/integration tests, but still needs broader end-to-end client-flow coverage.
- README/examples may show encoding problems in some shell sessions.

Resolved/reduced on 2026-05-08:

- Password registration is separated into `POST /register` and now sanitizes redirects, validates server-side, rejects duplicates, creates the user, and logs the user in.
- Default unit/integration coverage reached 100%; visual NiceGUI rendering remains covered by Playwright smoke tests.

Resolved/reduced on 2026-05-13:

- Password login and LNURL redirect now sanitize `redirect_to`.
- OIDC signing key rotation is implemented with persistent encrypted key material, stable JWKS `kid`, key retention windows, admin endpoints, and audit events.
