---
title: Open Questions
tags:
  - agent-memory/question
type: question
project: satoidc
status: active
updated: 2026-05-06
---

# Open Questions

- Should local database files be replaced by migrations plus seed/setup workflows for repeatable development?
- Should protocol compliance be covered by focused OIDC/OAuth2 tests beyond the current placeholder test package?
- Should README encoding be normalized? The root README currently renders mojibake in this shell session.
- Should JWKS and token signing use persistent key material with rotation instead of an in-memory generated RSA key?
- What is the intended permission taxonomy: root/admin/support only, or should developer/client-management permissions exist?
- Should `create_client` require developer permission rather than only authenticated session?
- Should LNURL `auth` action be removed until an explicit stateless authorization contract exists?
- Should time-sensitive OIDC token tests cover signed JWT `exp` validation end-to-end once persistent key rotation is implemented?
