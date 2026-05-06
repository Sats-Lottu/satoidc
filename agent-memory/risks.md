---
title: Risks And Pitfalls
tags:
  - agent-memory/state
  - agent-memory/todo
type: state
project: satoidc
status: active
updated: 2026-05-06
---

# Risks And Pitfalls

High priority:

- Password login redirects to submitted `redirect_to` without `safe_redirect`.
- RSA JWT/JWKS key is generated in memory at process import, so restarts and replicas invalidate or diverge token verification.
- OIDC key rotation is specified in `specs/features/oidc-key-rotation/`, but implementation still needs persistent key storage, `kid` headers, JWKS retention windows, admin authorization, and audit events.

Medium priority:

- Test coverage exists and passes, but remains partial around full browser OAuth authorization-code flows and browser-facing NiceGUI routes.
- Permission names are inconsistent: enum has `root`, `admin`, `support`; migration includes `DRAW_OPERATOR`; UI checks use `developer`, `admin`, `root`.
- LNURL callback marks challenge verified before signature validation, consuming the challenge on bad signature.
- LNURL registration can create a user with nullable identity fields and `nickname=None` despite non-null model expectation.
- Refresh grant is registered, but refresh token generation appears disabled by default.
- README has encoding problems and RS256/ES256 inconsistency.
