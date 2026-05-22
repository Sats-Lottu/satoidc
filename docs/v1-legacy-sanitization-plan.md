# V1 Legacy Sanitization Plan

Updated: 2026-05-22

This audit identifies legacy, temporary, inconsistent, or partially migrated
elements that should be resolved or deliberately accepted before the first
official SatOIDC release.

## Release Goal

SatOIDC v1 should expose one coherent contract for OAuth/OIDC, LNURL-auth,
runtime configuration, setup, permissions, operations, and documentation. The
release should avoid carrying temporary compatibility paths that would force
larger breaking changes immediately after publication.

## Audit Summary

| ID | Classification | Priority | Area | Status |
| --- | --- | --- | --- | --- |
| L01 | Remove | P0 | LNURL callback contract | Docs corrected; keep code/tests clean. |
| L02 | Migrate | P0 | Runtime config/setup | Open. |
| L03 | Refactor | P1 | Admin dashboard/services | Open. |
| L04 | Replace | P1 | Operational logs/audit events | Open. |
| L05 | Refactor | P1 | OAuth client destructive actions | Open. |
| L06 | Migrate | P1 | API/security docs and specs | Partially corrected. |
| L07 | Maintain temporarily | P2 | Draft specs and temporary task docs | Open. |
| L08 | Refactor | P2 | Enums for unsupported protocol values | Corrected for grants; signing enum tracks Authlib/Joserfc plus OpenBao RSA support. |
| L09 | Migrate | P2 | Local database development state | Decision recorded; workflow still open. |
| L10 | Replace | P2 | Load/conformance evidence placeholders | Open. |
| L11 | Refactor | P1 | UI/application logic separation | Started with OAuth client creation command endpoint. |
| L12 | Remove | P3 | Non-English code comments | Corrected. |

## Detailed Findings

### L01 - Removed LNURL `action=auth` still referenced in product docs

Problem: The LNURL stateless `auth` action was removed from the callback
contract, but `prd.md` still listed it as an open question and working
assumption.

Impact: Future agents could reintroduce an uncontracted callback action before
v1.

Risk: Security and wallet compatibility ambiguity around replay behavior,
session creation, and stateless authentication semantics.

Affected dependencies: `satoidc/satoidc/routes/lnurl_auth.py`,
`satoidc/satoidc/auth/lnurl.py`, `specs/flows/lnurl-auth.md`, PRD.

Priority: P0.

Strategy: Remove the product-level ambiguity. v1 supports only `register`,
`login`, and `link`. Add any future stateless auth behavior only through a new
spec, route tests, and security review.

Action taken: Updated `prd.md`.

### L02 - Runtime configuration has mixed current names, future aliases, and planned wizard ownership

Problem: Runtime code accepts current names and several `SATOIDC_*` aliases,
while specs still distinguish current, future, and planned names. Wizard-owned
mutable settings are now documented but not persisted or loaded by runtime.

Impact: Operators and future agents may treat planned settings as implemented,
or may store values that the runtime does not read.

Risk: Broken production bootstrap, confusing setup UI, and post-v1 breaking
changes in environment names.

Affected dependencies: `satoidc/satoidc/settings.py`,
`satoidc/satoidc/runtime_config.py`, setup wizard, Compose, `.env.example`,
runtime-config contract.

Priority: P0.

Strategy: Implement `setup_runtime_settings`, load persisted values after env
sources and before defaults, and update the runtime matrix to mark exactly which
aliases are accepted today. Do not persist raw secrets.

Rollback: Keep current env-only path authoritative; if persisted settings fail,
operators can delete `setup_runtime_settings` rows and restart with env values.

### L03 - Admin dashboard still mixes route UI with admin query/commit behavior

Problem: Profile and OAuth client persistence-heavy actions were extracted into
services, but admin dashboard query and mutation logic still partially lives in
route closures.

Impact: Pagination, audit, logging, and error handling are harder to test
without browser e2e.

Risk: Scaling fixes and safety checks drift between route and service layers.

Affected dependencies: `satoidc/satoidc/routes/dashboard.py`,
`satoidc/satoidc/services/admin_dashboard.py`,
`satoidc/satoidc/auth/permissions.py`.

Priority: P1.

Strategy: Finish service extraction for admin approvals/denials, paginated
queries, inactive permissions, and destructive client operations. Keep route
modules focused on NiceGUI rendering and notification mapping.

Rollback: Service extraction can be reverted without schema changes if route
behavior remains covered by unit/e2e tests.

### L04 - Operational events are inconsistent between logs and durable audit

Problem: Some security-relevant operations emit structured-ish `logging.extra`
fields, OIDC key lifecycle writes database audit rows, and many UI mutations
still rely primarily on notifications.

Impact: Operators cannot reliably filter or correlate auth, OIDC, LNURL, setup,
email, and admin mutation failures.

Risk: Incident response gaps and inconsistent production observability
immediately after v1.

Affected dependencies: auth routes/services, `OidcSigningKeyAuditEvent`,
permission request services, setup wizard, email delivery, operational docs.

Priority: P1.

Strategy: Implement the Operational Observability Baseline: event taxonomy,
JSON-friendly formatter or adapter, secret redaction tests, and clear separation
between durable audit events and stdout logs.

Rollback: Logging changes should be additive. If JSON formatting fails in a
deployment, fallback to standard formatter while keeping event names in `extra`.

### L05 - OAuth client deletion lacks release-grade destructive action safety

Problem: Client management exists, but the PRD and admin-dashboard spec still
track missing typed confirmation for destructive OAuth client deletion.

Impact: A developer/admin can accidentally delete a client and break relying
parties.

Risk: User-visible outages and support burden after v1.

Affected dependencies: developer dashboard UI, `services/oauth_clients.py`,
browser e2e tests.

Priority: P1.

Strategy: Require typed client name or id confirmation, keep secret rotation
one-time display semantics, and add e2e coverage for disabled delete button
until confirmation matches.

### L06 - Specs and docs contained stale contract statements

Problem: `specs/flows/page-security.md` still claimed `developer` was missing
from `PermissionsEnum`; `docs/architecture.md` omitted recovery schemas;
`specs/index.md` still listed `P0-02` as open even after proxy rate limiting
docs were completed.

Impact: Agents could implement work against obsolete contracts.

Risk: Duplicate permission models, rework in page security, and stale backlog
priorities.

Affected dependencies: specs index, page-security flow, architecture docs,
PRD.

Priority: P1.

Strategy: Keep specs status and product backlog traceability updated in the
same change that completes or resolves a contract.

Action taken: Updated affected docs/specs.

### L07 - Temporary execution task files remain mixed with release work

Problem: `docs/priority-execution-tasks/` is explicitly temporary but still
contains coordination material and completed subtasks.

Impact: Release planning can confuse active product debt with historical
multi-agent execution scaffolding.

Risk: Agents follow stale task packets instead of current specs/backlog.

Affected dependencies: `docs/priority-execution-backlog.md`,
`docs/priority-execution-tasks/`, `docs/priority-execution-history.md`.

Priority: P2.

Strategy: Before v1, remove fully completed task files and summarize outcomes in
history. Keep only open execution tasks or replace the temporary folder with a
v1 release checklist.

### L08 - Protocol enums expose future or unsupported grant/response concepts

Problem: `GrantTypeEnum` included `client_credentials` and device code values,
while client creation currently supports only authorization code and refresh
token. Response type comments also referenced future implicit/hybrid values.

Impact: Developers may assume unsupported grants are part of the v1 contract.

Risk: Accidental UI/API exposure or persistence of unsupported client metadata.

Affected dependencies: `satoidc/satoidc/enums.py`,
`satoidc/satoidc/services/oauth_clients.py`, client registration spec.

Priority: P2.

Strategy: Either remove unsupported enum members before v1 or move them to an
explicit `FutureGrantType`/documentation-only section. The v1 client metadata
contract should advertise only `authorization_code` and `refresh_token`.

Action taken: Removed unsupported `GrantTypeEnum` members for client
credentials and device code. Comments were normalized to English and future
implicit/hybrid wording was clarified. `JwkAlgEnum` now tracks the JWS
algorithm names that are supported by both the Authlib/Joserfc dependency and
the current OpenBao Transit RSA signing backend: `RS256`, `RS384`, `RS512`,
`PS256`, `PS384`, and `PS512`.

### L09 - Local database files are disposable, not canonical

Problem: The project supports local SQLite database files, but v1 development
must not treat those files as canonical project state.

Impact: Local behavior can drift from clean bootstrap paths.

Risk: Agents diagnose local database drift instead of reproducing issues from a
known seed.

Affected dependencies: local development docs, setup wizard, test fixtures,
`.gitignore`.

Priority: P2.

Decision: Local database files may continue to exist only as disposable
development artifacts.

Strategy: Keep SQLite support, but add deterministic migration plus seed/setup
workflows for v1 development and avoid checking in runtime database files.

### L10 - Conformance and load evidence are configured but not recorded

Problem: The OIDF local runner and Locust smoke path exist, but there is no
recorded Basic OP evidence or PostgreSQL load baseline.

Impact: README/PRD must avoid implying certification or production capacity.

Risk: Overstated release claims and weak sizing guidance.

Affected dependencies: `docs/conformance.md`, `oidf-conformance/`,
`docs/load-testing.md`, `tests/load/locustfile.py`, PRD.

Priority: P2.

Strategy: Run the OIDF Basic OP suite and PostgreSQL load baseline, record
results under dated docs, and only then update public release claims.

### L11 - Web pages still own too much application mutation logic

Problem: Some form flows use POST endpoints and schema objects while other
NiceGUI interactions use event handlers and notifications. Several web page
modules still own application mutation logic directly, such as changing profile
state, approving requests, creating or editing clients, or triggering setup
actions.

Impact: Page modules become hard to test without browser automation, mutations
are coupled to UI events, and future clients or automation cannot reuse the same
behavior through a clear application boundary.

Risk: Harder testing, inconsistent user experience, duplicated validation,
route-local transaction handling, and expensive refactors after v1.

Affected dependencies: profile, create-client, dashboards, shared UI
components, setup wizard, route services, UI backlog.

Priority: P1.

Strategy: Define the v1 UI mutation pattern:

- NiceGUI pages render state, collect input, display validation/errors, and
  navigate.
- Application mutations live behind service/use-case functions and, where a
  browser form or cross-page action is involved, an explicit command endpoint.
- Command endpoints should use clear HTTP method semantics: `POST` for create
  or action commands, `PUT`/`PATCH` for idempotent or partial updates when the
  resource model is clear, and `DELETE` for destructive deletes with explicit
  confirmation.
- The project is not a stateless public REST API. Endpoints may use the existing
  session, CSRF/session protections, and server-rendered/NiceGUI flows, but the
  boundary should still be explicit and testable.
- Page modules should not directly own database commits for domain mutations.

Action started: Added `POST /dashboard/developer/clients` as a session-backed
command endpoint for OAuth client creation. The endpoint derives v1-safe
metadata from guided form fields, checks developer/admin authorization, calls
the client service, and stores redirect-safe flash state for page feedback.

### L12 - Non-English code comments contradicted repository language policy

Problem: A few comments in Python source were Portuguese while the repository
language policy requires English persisted content.

Impact: Minor consistency issue and future copy/paste drift.

Risk: Low.

Affected dependencies: `satoidc/satoidc/enums.py`,
`satoidc/satoidc/auth/middleware.py`.

Priority: P3.

Strategy: Keep code comments and persisted docs in English.

Action taken: Comments normalized.

## Migration And Refactoring Plan

### Phase 1 - Contract cleanup before release branch

1. Remove stale product/spec statements already contradicted by implementation.
2. Freeze v1-supported public endpoints and OIDC/LNURL actions.
3. Decide whether unsupported enum members stay internal or are removed.
4. Convert draft specs that describe implemented behavior to `implemented`, or
   mark them explicitly as future design docs.

Breaking changes: Removing unsupported enum members can affect imports/tests but
should not affect external API clients if those values were never accepted.

Compatibility: Keep current endpoint paths. Do not rename `/oauth/token`,
`/oauth/userinfo`, or `/.well-known/jwks.json` before conformance testing.

### Phase 2 - Setup/runtime configuration stabilization

1. Add `setup_runtime_settings` via Alembic autogenerate.
2. Implement typed read/write service and validators.
3. Load persisted settings after env sources.
4. Update setup reconfiguration UI to edit only unlocked wizard-owned values.
5. Add precedence, masking, and locked-field tests.

Breaking changes: None if env precedence is preserved.

Rollback: Drop or ignore persisted setting rows and restart with env-only
configuration.

### Phase 3 - Admin/service boundary and safety

1. Move remaining admin query/mutation logic behind services.
2. Add typed confirmation for OAuth client deletion.
3. Add server-side pagination for admin users, clients, requests, and inactive
   permissions.
4. Move page-owned mutation logic toward service-backed command endpoints with
   explicit HTTP method semantics.
5. Emit sanitized logs/audit events for admin mutations.

Breaking changes: UI behavior changes only. Preserve model/API storage.

Rollback: Feature-flag or revert route-level UI changes; service helpers should
not require migration unless audit schema changes are introduced.

### Phase 4 - Observability and evidence

1. Implement structured operational logging baseline.
2. Run OIDF Basic OP conformance and record evidence.
3. Run PostgreSQL load baseline and record results.
4. Update README/PRD only with evidence-backed claims.

Breaking changes: None expected.

Rollback: Logging formatter can fall back to plain logs; evidence docs can mark
failures without blocking runtime.

### Phase 5 - Temporary artifact retirement

1. Remove or archive completed temporary task files.
2. Ensure `docs/priority-execution-backlog.md` contains only open work.
3. Keep historical analysis only under `docs/archive/`.
4. Verify `agent-memory/` does not contradict specs or PRD.

## V1 Compatibility Boundaries

Keep for v1:

- `/authorize`
- `/oauth/authorize`
- `/oauth/token`
- `/oauth/userinfo`
- `/oauth/introspect`
- `/oauth/revoke`
- `/.well-known/openid-configuration`
- `/.well-known/jwks.json`
- `/auth/lnurl/callback`
- LNURL actions `register`, `login`, `link`
- Permission taxonomy `root`, `admin`, `developer`, `support`
- Current environment variable names, with documented `SATOIDC_*` migration
  targets where already implemented or planned.

Do not expose for v1 without a new spec:

- LNURL `action=auth`
- Implicit or hybrid OIDC flows
- Dynamic client registration
- Device code grant
- Client credentials grant
- Public admin REST API
- Raw wizard-owned secret storage

## Remaining Priority Actions

| Priority | Action |
| --- | --- |
| P0 | Implement wizard-owned persisted settings or explicitly defer reconfiguration mutation from v1. |
| P0 | Freeze v1 protocol contract and keep unsupported protocol values out of code and docs. |
| P1 | Add OAuth client delete typed confirmation. |
| P1 | Implement structured operational logging baseline. |
| P1 | Finish admin dashboard service extraction and pagination. |
| P1 | Separate UI rendering from application mutation logic through services and command endpoints. |
| P2 | Run OIDF Basic OP conformance and record evidence. |
| P2 | Publish PostgreSQL `/oauth/token` load baseline. |
| P2 | Retire temporary task files once their open work is promoted into backlog/specs. |
| P2 | Add repeatable local seed/setup workflows so local database files remain disposable. |
| P3 | Normalize UI validation conventions and add inline client-form errors. |

## Decisions Proposed

- Treat the v1 LNURL callback action set as closed: `register`, `login`,
  `link`.
- Treat current OAuth/OIDC endpoint paths as stable for v1.
- Treat reverse-proxy rate limiting as an operational requirement, not in-app
  middleware.
- Treat `setup_runtime_settings` as the only approved wizard-owned persistence
  shape.
- Treat database URLs and all raw secrets as deployment-owned, not
  wizard-owned.
- Treat dynamic registration, device code, client credentials, implicit, and
  hybrid flows as out of scope for v1.
- Treat NiceGUI pages as UI composition only. State-changing application logic
  should live in services and explicit command endpoints with clear HTTP method
  semantics, while still using SatOIDC's session-based server app model rather
  than a stateless public REST API.
