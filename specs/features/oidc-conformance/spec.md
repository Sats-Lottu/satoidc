# Spec: OIDC Conformance Evidence

## Status

- Status: draft
- Owner: TBD
- Created: 2026-05-18
- Updated: 2026-05-18
- Product source:
  - `prd.md`
  - `relatorio_tecnico.md`
- Related code:
  - `satoidc/satoidc/routes/oauth2.py`
  - `satoidc/satoidc/auth/oauth2.py`
  - `satoidc/satoidc/auth/oidc.py`
  - `satoidc/satoidc/fastapi_oauth2/`
- Related specs:
  - `specs/contracts/oidc.md`
  - `specs/flows/authorization-code.md`
  - `specs/flows/token-lifecycle.md`
  - `specs/features/quality-testing/spec.md`

## Intent

Track the evidence needed to claim OIDC interoperability beyond the project's
own focused tests.

## Context

SatOIDC has route and e2e coverage for key OIDC flows, but there is no recorded
OpenID Foundation Basic OP conformance result. Product readiness should not
claim conformance until evidence exists.

## Scope

In scope:

- Define the target OpenID Provider conformance profile.
- Document current supported response types, grant types, scopes, signing
  algorithms, client authentication methods, and known limits.
- Run or document a manual conformance pass.
- Capture deviations and follow-up tasks.
- Add relying-party compatibility examples after conformance targets are clear.

Out of scope:

- Formal OpenID certification submission as an immediate requirement.
- Implicit or hybrid flow support.
- Dynamic client registration unless a future product requirement adds it.

## Requirements

- `docs/conformance.md` must state current claims and evidence.
- The conformance profile must match advertised discovery metadata.
- Any unsupported OIDC feature must be absent from discovery or documented as
  intentionally unsupported.
- Test data must avoid real secrets, production keys, and persistent local
  operator data.

## Acceptance Criteria

- Given SatOIDC advertises `response_types_supported=["code"]`, then conformance
  testing targets Authorization Code flow only.
- Given Basic OP tests are run, then results and known deviations are recorded in
  `docs/conformance.md`.
- Given a conformance failure identifies a product bug, then it is added to
  `docs/known-issues.md` or a feature spec.
- Given a relying-party compatibility example is documented, then it states
  client type, auth method, redirect URI behavior, scopes, and token expectations.

## Test Plan

- Manual: run the OpenID Foundation conformance suite against a disposable local
  SatOIDC instance.
- Automated future work: add a CI job only after manual setup is stable and not
  too slow for regular validation.
- Regression: keep existing OAuth/OIDC route and Playwright e2e tests as release
  gates.
