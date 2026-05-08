---
title: Risks And Pitfalls
tags:
  - agent-memory/state
  - agent-memory/todo
type: state
project: satoidc
status: active
updated: 2026-05-08
---

# Risks And Pitfalls

High priority:

- RSA JWT/JWKS key is generated in memory at process import, so restarts and replicas invalidate or diverge token verification.
- OIDC key rotation is specified in `specs/features/oidc-key-rotation/`, but implementation still needs persistent key storage, `kid` headers, JWKS retention windows, admin authorization, and audit events.
- Full browser OAuth authorization-code e2e coverage is still incomplete; current Playwright tests cover public pages, responsiveness, and well-known endpoint smoke behavior.
- Password login redirects to submitted `redirect_to` without `safe_redirect`; password registration now sanitizes this path, but login still needs the same hardening.

Medium priority:

- Permission names are inconsistent: enum has `root`, `admin`, `support`; migration includes `DRAW_OPERATOR`; UI checks use `developer`, `admin`, `root`.
- LNURL callback marks challenge verified before signature validation, consuming the challenge on bad signature.
- LNURL registration can create a user with nullable identity fields and `nickname=None` despite non-null model expectation.
- Refresh grant has focused unit/integration tests, but still needs broader end-to-end client-flow coverage.
- README/examples may show encoding problems in some shell sessions.

Resolved/reduced on 2026-05-08:

- Password registration is separated into `POST /register` and now sanitizes redirects, validates server-side, rejects duplicates, creates the user, and logs the user in.
- Default unit/integration coverage reached 100%; visual NiceGUI rendering remains covered by Playwright smoke tests.
