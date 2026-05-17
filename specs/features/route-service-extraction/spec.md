# Spec: Route Service Extraction

## Status

- Status: implemented
- Owner: TBD
- Created: 2026-05-16
- Updated: 2026-05-17
- Related code:
  - `satoidc/satoidc/routes/profile.py`
  - `satoidc/satoidc/routes/dashboard.py`
  - `satoidc/satoidc/routes/register.py`
  - `satoidc/satoidc/auth/`
  - `satoidc/satoidc/models/`
- Related specs:
  - `specs/flows/profile.md`
  - `specs/flows/client-registration.md`
  - `specs/features/permission-requests/spec.md`

## Intent

Reduce UI route complexity by moving persistence-heavy business actions from
NiceGUI event handlers into focused service/use-case helpers.

## Context

NiceGUI route files currently mix page composition, dialog state, validation,
SQLAlchemy access, and mutation logic. This helped the MVP move quickly, but it
increases navigation cost and makes unit tests harder.

## Scope

In scope:

- Extract focused helpers for account profile actions.
- Extract focused helpers for developer/admin client actions.
- Keep UI rendering and NiceGUI component wiring in route modules.
- Add unit tests around extracted behavior.

Out of scope:

- Rewriting the UI framework.
- Introducing a broad dependency-injection framework.
- Changing user-facing behavior without a separate flow spec.

## Rules

- Services should accept explicit inputs and sessions rather than reaching into
  NiceGUI globals.
- Route handlers should translate UI events into service calls and display
  results.
- Existing permission helpers should remain the source of truth for access
  decisions.
- Keep extraction incremental and behavior-preserving.

## Candidate Use Cases

- Change profile nickname.
- Change profile email.
- Change profile password.
- Link, relink, and unlink LNURL wallet.
- Create, edit, disable/delete, and rotate OAuth client credentials.
- Approve or deny developer permission requests.

## Acceptance Criteria

- Given profile service helpers, when unit tests call them directly, then they
  validate and mutate account data without constructing a NiceGUI page.
- Given dashboard client service helpers, when unit tests call them directly,
  then client metadata validation and secret rotation remain covered outside UI
  rendering tests.
- Given route modules after extraction, when existing e2e tests run, then user
  behavior remains unchanged.
- Given lint checks, then removed complexity suppressions are not reintroduced
  unless justified by UI glue.

## Test Plan

- Unit: service helpers for validation and persistence behavior.
- Integration: existing route/API tests for database side effects.
- E2E: existing authenticated UI and OAuth browser tests.
- Regression: verify permission checks and one-time secret display behavior.

## Implementation Notes

Start with one narrow vertical slice, such as profile email/password actions,
before extracting the whole dashboard. Keep service modules close to existing
domains, for example `satoidc/satoidc/services/profile.py` and
`satoidc/satoidc/services/oauth_clients.py`, only if that matches the local
code shape during implementation.

Implemented on 2026-05-17:

- `satoidc/satoidc/services/profile.py` owns profile nickname, email,
  password, wallet unlink, and wallet-link challenge persistence.
- `satoidc/satoidc/services/oauth_clients.py` owns OAuth client metadata
  validation plus client creation, update, secret rotation, status toggle, and
  deletion persistence.
- Existing permission request helpers in `satoidc/satoidc/auth/permissions.py`
  remain the source of truth for developer-access requests and decisions.
- Focused unit tests cover profile services and OAuth client service
  persistence behavior.

## Traceability

- Code: `satoidc/satoidc/routes/`
- Tests: `satoidc/tests/`
- Docs: `docs/priority-execution-backlog.md`
- Decisions: `agent-memory/decisions.md`
