---
title: Open Questions
tags:
  - agent-memory/question
type: question
project: satoidc
status: active
updated: 2026-05-22
---

# Open Questions

No open questions are currently tracked.

## Resolved

- 2026-05-22: Local database files are disposable development artifacts, not canonical project state. Repeatable environments should use migrations plus seed/setup workflows.
- 2026-05-22: Time-sensitive OIDC token tests should cover signed JWT `exp` validation end-to-end after persistent key rotation is implemented, including real signing, JWKS resolution, expiration, and rejection of expired tokens.
- 2026-05-20: Refresh-token rotation, old refresh-token rejection, access-token revocation, introspection ownership, and UserInfo scope protection are covered by browser/client e2e token lifecycle tests.
- 2026-05-20: LNURL `action=auth` was removed from the callback contract until an explicit stateless authorization contract exists; supported LNURL actions are `register`, `login`, and `link`.
- 2026-05-17: Outbound HTTP/web request implementation should use async `httpx`, recorded as a direct Poetry dependency.
- 2026-05-17: Hardened OIDC signing has a first supported OpenBao/Vault-compatible Transit implementation with Testcontainers OpenBao coverage; broader operator deployment shape remains documentation/deployment work rather than a blocker for the code path.
- 2026-05-17: Email verification and password recovery are implemented with single-use hashed tokens and email delivery integration coverage.
- 2026-05-17: Persistence-heavy profile and OAuth client NiceGUI actions were extracted into service helpers.
- 2026-05-15: Protocol compliance is now covered by focused OAuth/OIDC tests plus browser authorization-code e2e for public PKCE and confidential `client_secret_post` clients.
- 2026-05-15: README/examples/legal/docs encoding was checked for mojibake patterns and no matches remain.
- 2026-05-13: JWKS and token signing use persisted signing keys with rotation instead of a process-local generated RSA key.
- 2026-05-13: Permission taxonomy includes `root`, `admin`, `developer`, and `support`; `developer` is first-class.
- 2026-05-13: `/create_client` requires developer-like access through `page_security`.
