---
title: Open Questions
tags:
  - agent-memory/question
type: question
project: satoidc
status: active
updated: 2026-05-16
---

# Open Questions

- Should local database files be replaced by migrations plus seed/setup workflows for repeatable development?
- Should LNURL `auth` action be removed until an explicit stateless authorization contract exists?
- Should time-sensitive OIDC token tests cover signed JWT `exp` validation end-to-end once persistent key rotation is implemented?
- What exact local OpenBao deployment shape should SatOIDC support first for hardened OIDC signing: separate compose profile, external endpoint only, or documented operator setup?
- Should refresh-token revocation be covered by a full browser/client e2e flow, beyond the current focused unit/integration coverage and authorization-code e2e refresh issuance check?

## Resolved

- 2026-05-15: Protocol compliance is now covered by focused OAuth/OIDC tests plus browser authorization-code e2e for public PKCE and confidential `client_secret_post` clients.
- 2026-05-15: README/examples/legal/docs encoding was checked for mojibake patterns and no matches remain.
- 2026-05-13: JWKS and token signing use persisted signing keys with rotation instead of a process-local generated RSA key.
- 2026-05-13: Permission taxonomy includes `root`, `admin`, `developer`, and `support`; `developer` is first-class.
- 2026-05-13: `/create_client` requires developer-like access through `page_security`.
