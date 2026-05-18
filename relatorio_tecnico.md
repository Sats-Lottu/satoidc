# SatOIDC Technical And Product Readiness Report

Updated: 2026-05-18

## 1. Executive Findings

SatOIDC is a usable beta with substantial core functionality already in place:
OIDC authorization-code flow with PKCE, refresh tokens, profile and client
management, email verification/recovery, Docker Compose, PostgreSQL integration
coverage, and OpenBao/Vault-compatible Transit signing.

The largest remaining blockers for a self-hosted product label are specific and
actionable:

1. **Security:** production rate limiting is delegated to the reverse proxy; a
   deployment that exposes SatOIDC directly is not hardened.
2. **LNURL registration:** wallet-created users now use the default nickname
   `satoshi` when no nickname is supplied.
3. **Operations:** backup/restore/upgrade/reverse-proxy runbooks are missing.
4. **Observability:** logs and audit data exist, but there is no structured
   operator logging baseline or metrics guidance.
5. **Admin UX:** dashboards use fixed limits, and OAuth client deletion lacks
   strong confirmation.

## 2. Repository Inventory

| Area | Status | Evidence | Notes |
| --- | --- | --- | --- |
| Application shell | Confirmed | `satoidc/satoidc/main.py` | FastAPI + NiceGUI app integration. |
| Routes/UI | Confirmed | `satoidc/satoidc/routes/` | NiceGUI composition and FastAPI endpoints. |
| Service layer | Partial | `satoidc/satoidc/services/profile.py`, `oauth_clients.py`, `email_tokens.py`, `email_delivery.py` | Profile/client/email mutations are extracted; admin dashboard still contains query and commit logic. |
| Auth/OIDC | Confirmed | `satoidc/satoidc/auth/`, `satoidc/satoidc/fastapi_oauth2/` | Authlib adapter, signing, permissions, middleware. |
| Persistence | Confirmed | `satoidc/satoidc/models/`, `satoidc/migrations/` | SQLAlchemy models and Alembic migrations. |
| Tests | Confirmed | `satoidc/tests/`, `satoidc/pyproject.toml` | Unit, property, API security, integration, load, and e2e task commands exist. |
| Docs/memory | Confirmed | `docs/`, `specs/`, `agent-memory/` | Good engineering memory; operator docs are still thin. |

## 3. Architecture Review

### Confirmed Strengths

- `satoidc/satoidc/services/` now contains focused service modules for profile,
  OAuth clients, and email tokens/delivery.
- Transit signing is isolated behind `satoidc/satoidc/auth/oidc_signing_backends.py`.
- The project records the decision to use async `httpx` for outbound HTTP/web
  calls.
- Authlib synchronous operations are intentionally kept behind threadpool
  helpers instead of mixing async SQLAlchemy sessions into Authlib callbacks.

### Remaining Architecture Risks

- `satoidc/satoidc/routes/dashboard.py` still performs admin dashboard queries
  and commits for permission request approval/denial. This is not automatically
  wrong for NiceGUI, but it means the service extraction is partial.
- Fixed `.limit(10)` queries in `dashboard.py` truncate admin views and prevent
  scalable navigation through users, clients, and permission requests.
- Authlib threadpool behavior needs measured limits before the project publishes
  capacity guidance.

### Recommendation

Avoid broad rewrites. Continue extracting only repeated or high-risk business
logic from route closures into services, starting with admin permission request
approval/denial and paginated dashboard queries.

## 4. Security Review

| Finding | Status | Evidence | Risk | Recommendation | Acceptance Criteria |
| --- | --- | --- | --- | --- | --- |
| Rate limiting delegated to reverse proxy | Decision | `docs/operations/reverse-proxy.md`. | Operators may accidentally expose SatOIDC without throttling. | Treat direct public exposure as not production-hardened; document NGINX and Traefik examples. | Deployment docs include clear alert and example configs. |
| LNURL default nickname | Implemented rule | `satoidc/satoidc/routes/lnurl_auth.py` uses `satoshi`. | Regression could reintroduce null nickname. | Keep focused test coverage. | Regression test proves LNURL registration creates `nickname="satoshi"`. |
| Redirect safety | Confirmed implemented | `satoidc/satoidc/utils.py`, `satoidc/tests/test_security.py`, `test_security_properties.py`. | Lower residual risk. | Keep property-based tests. | External and control-character redirect targets are rejected. |
| External signing backend | Confirmed implemented | `satoidc/satoidc/auth/oidc_signing_backends.py`. | Operators can avoid DB-held private key material when Transit is configured. | Add operator runbook for OpenBao/Vault setup and failure modes. | Fresh Transit deployment can sign ID Tokens and publish JWKS. |
| Destructive client deletion | Confirmed gap | `satoidc/satoidc/routes/dashboard.py` `delete_client_dialog`. | Accidental client deletion. | Require typed confirmation. | Delete button stays disabled until expected text matches. |

## 5. OAuth2/OIDC Protocol Review

- Authorization Code with PKCE, refresh token support, userinfo,
  introspection, revocation, discovery, and JWKS are implemented.
- The test suite covers many protocol behaviors, including time-sensitive token
  and challenge behavior.
- OpenID Foundation Basic OP conformance is not yet documented or automated.
- Refresh-token revocation has focused coverage but still needs broader
  end-to-end client-flow coverage.

Recommendation: create `docs/conformance.md` before adding CI automation. It
should define target profiles, test clients, expected deviations, and evidence
format.

## 6. Persistence And Migration Review

- Alembic migrations are versioned under `satoidc/migrations/versions/`.
- Project convention requires migrations to be generated with
  `poetry run alembic revision --autogenerate -m "<message>"` and then minimally
  edited.
- `docs/database-support-matrix.md` documents SQLite and PostgreSQL support.
- `docs/local-development-troubleshooting.md` documents a local SQLite drift
  case for missing revision `7b0c2a4d9f31`.
- No Alembic locking mechanism was confirmed. Do not document or promise one
  unless implemented.

Recommendation: add production migration runbook sections for pre-upgrade
backup, migration execution, rollback expectations, and failure recovery.

## 7. Self-Hosted Operations Review

| Capability | Current State | Gap |
| --- | --- | --- |
| Install | Compose/env examples exist. | Needs operator quick-start with verification steps. |
| Configure | Settings are centralized. | Full env var reference should be published. |
| Email | SMTP/console/disabled modes exist. | Needs delivery troubleshooting docs. |
| Transit | Backend exists. | Needs OpenBao/Vault setup and failure-mode docs. |
| Backup/restore | Underlying DBs support it. | No production runbook. |
| Reverse proxy | Deployment docs exist. | Needs TLS, forwarded header, real IP, and rate-limit guidance. |
| Upgrade | Alembic startup path exists. | Needs versioned upgrade checklist. |

## 8. Observability Review

Current state:

- Application modules use standard `logging.getLogger`.
- OIDC signing key audit events are persisted through
  `OidcSigningKeyAuditEvent`.
- There is no confirmed structured logging baseline.
- There is no confirmed metrics exporter or OpenTelemetry tracing setup.

Corrections:

- Prometheus should be discussed as a metrics target, not a log ingestion target.
- JSON logs are suitable for stdout collection by Loki, ELK, Datadog, Splunk, or
  container platforms.
- `structlog` is an option, not a requirement. A JSON formatter for standard
  logging may be enough for the first milestone.

Recommended first step: define an event taxonomy for auth failures, admin
mutations, token issuance errors, email delivery errors, and Transit failures.

## 9. UI/UX Review

Confirmed issues:

- `delete_client_dialog` lacks typed confirmation.
- Admin lists use fixed `.limit(10)` queries and no visible pagination.
- Dense admin workflows will degrade as users, clients, and permission requests
  grow.

Positive baseline:

- `DESIGN.md` defines product UI conventions.
- Shared UI helpers exist in `satoidc/satoidc/routes/ui_components.py`.
- Responsive patterns exist, but the admin data views still need scale testing.

Recommendations:

- Add text confirmation for destructive actions.
- Replace fixed limits with server-side pagination controls.
- Use denser operational layouts for admin dashboards, not landing-page styling.
- Add clear empty, loading, and error states for admin tables.
- Keep OAuth client forms precise for developers, but use option controls for
  common cases where possible.

## 10. Responsive And Multiplatform Design Review

SatOIDC should be verified across:

- desktop widths for admin/operator dashboards;
- tablet widths for touch-friendly navigation;
- mobile widths for login, register, recovery, profile, and LNURL QR flows;
- keyboard navigation for all dialogs and forms.

Recommended checks:

- no horizontal overflow in dashboard and client forms;
- QR dialogs remain visible and actionable on mobile;
- icon-only buttons have labels/tooltips;
- destructive modals keep primary/secondary actions distinct;
- table rows collapse or paginate cleanly on narrow screens.

## 11. Accessibility Review

Current accessibility status is not fully verified. Avoid claiming WCAG 2.2 AA
compliance until tested.

Required checks:

- visible focus indicators;
- dialog focus trapping and return focus;
- accessible labels for icon-only controls;
- contrast checks for light/dark theme combinations;
- keyboard path through login, registration, recovery, profile, dashboard, and
  client management;
- screen-reader behavior for LNURL QR dialogs and one-time secret displays.

## 12. Testing And Quality Review

Confirmed task commands in `satoidc/pyproject.toml`:

- `poetry run task test`
- `poetry run task test_e2e`
- `poetry run task test_unit`
- `poetry run task test_property`
- `poetry run task test_api_security`
- `poetry run task test_integration`
- `poetry run task test_load`
- `poetry run task test_load_ui`
- `poetry run task test_all`

Current gaps:

- Load tests exist as commands but need executed baseline reports.
- OIDC Basic OP conformance is not yet captured.
- Refresh-token revocation needs broader e2e coverage.
- Accessibility checks are not documented as release gates.

## 13. Documentation Review

Strong points:

- `docs/`, `specs/`, and `agent-memory/` preserve architecture, decisions, and
  execution history.
- `docs/local-development-troubleshooting.md` documents the recent Alembic drift
  issue.

Missing operator docs:

- backup/restore;
- upgrade/migration failure handling;
- reverse proxy and TLS;
- SMTP/email delivery;
- Transit setup and failures;
- observability/logging;
- OIDC conformance and relying-party compatibility.

## 14. Implementation Improvement Backlog

| ID | Priority | Effort | Impact | Task | Acceptance Criteria |
| --- | --- | --- | --- | --- | --- |
| IB01 | P0 | S | High | Keep LNURL default nickname valid | LNURL registration creates `User.nickname == "satoshi"`; regression test remains. |
| IB02 | P1 | M | High | Add structured logging baseline | Auth failures and admin mutations produce JSON logs to stdout. |
| IB03 | P1 | S | Medium | Move admin approval/denial commits into a service | `dashboard.py` calls service functions; unit tests cover approval/denial. |

## 15. Architecture Improvement Backlog

| ID | Priority | Effort | Impact | Task | Acceptance Criteria |
| --- | --- | --- | --- | --- | --- |
| AR01 | P2 | M | Medium | Add paginated dashboard query service | Admin lists can request page, size, total count, and rows from service helpers. |
| AR02 | P2 | M | Medium | Document Authlib threadpool capacity | Load-test results define practical deployment guidance. |

## 16. Security Improvement Backlog

| ID | Priority | Effort | Impact | Task | Acceptance Criteria |
| --- | --- | --- | --- | --- | --- |
| SEC01 | P0 | S | High | Configure reverse-proxy auth rate limiting | NGINX/Traefik or equivalent throttles login/register/recovery/LNURL routes before requests reach SatOIDC. |
| SEC02 | P1 | M | Medium | Add audit/log taxonomy for sensitive actions | Auth failures, admin actions, token errors, and Transit failures have consistent event names. |

## 17. UI/UX Improvement Backlog

| ID | Priority | Effort | Impact | Task | Acceptance Criteria |
| --- | --- | --- | --- | --- | --- |
| UX01 | P1 | S | Medium | Add typed confirmation for client deletion | Delete action is disabled until confirmation text matches. |
| UX02 | P2 | M | Medium | Add server-side dashboard pagination | Admin dashboard exposes pagination controls and no longer truncates silently. |
| UX03 | P2 | M | Medium | Add accessibility smoke checklist | Keyboard/focus/dialog checks are documented and run before release. |

## 18. Documentation/Ops Improvement Backlog

| ID | Priority | Effort | Impact | Task | Acceptance Criteria |
| --- | --- | --- | --- | --- | --- |
| DOC01 | P1 | M | High | Write operator runbook | Backup, restore, upgrade, health check, and incident procedures exist. |
| DOC02 | P1 | S | High | Document reverse proxy setup | NGINX and Traefik examples cover TLS, throttling, and forwarded headers. |
| DOC03 | P1 | S | Medium | Document SMTP/email modes | Operators can configure and troubleshoot delivery modes. |
| DOC04 | P1 | M | High | Document Transit deployment | Fresh OpenBao/Vault setup can be followed and validated. |
| DOC05 | P3 | M | Medium | Document OIDC conformance | Current conformance targets and results are recorded. |

## 19. Release Blockers

Self-hosted MVP blockers:

1. Reverse-proxy rate limiting has not been validated in a production-like deployment.
2. Operator backup/restore/upgrade runbook is still missing.

Production 1.0 blockers:

1. No documented load baseline.
2. No OIDC Basic OP conformance evidence.
3. No documented accessibility release checks.
4. No server-side admin pagination.

## 20. Quick Wins

1. Keep the `nickname="satoshi"` LNURL registration regression test.
2. Add typed confirmation to `delete_client_dialog`.
3. Add a first `docs/operations/runbook.md` with backup and restore commands.
4. Add `docs/conformance.md` as a placeholder with target profiles and current
   status.

## 21. Risks And Tradeoffs

- **Reverse-proxy rate limiting:** proxy-level limiting protects the Python app
  earlier and fits self-hosted NGINX/Traefik deployments, but it requires
  explicit operator setup and correct forwarded IP behavior.
- **Standard logging vs structlog:** standard logging with JSON formatter is
  simpler; `structlog` offers better event discipline but adds dependency and
  migration work.
- **NiceGUI route complexity:** some UI logic will naturally stay in route files;
  extract business rules and repeated data access without forcing a full frontend
  rewrite.
- **Authlib threadpool boundary:** pragmatic for current Authlib integration, but
  capacity must be measured rather than assumed.

## 22. Appendix: Evidence Table

| Finding | Status | Local Evidence | Risk | Next Action |
| --- | --- | --- | --- | --- |
| LNURL default nickname | Implemented rule | `satoidc/satoidc/routes/lnurl_auth.py` | Regression risk | Keep focused test. |
| Reverse-proxy rate limiting | Delegated requirement | `docs/operations/reverse-proxy.md` | Direct exposure is not hardened | Operators must configure NGINX, Traefik, or equivalent. |
| Service layer extraction | Partial | `satoidc/satoidc/services/`, `dashboard.py` commits/queries | Some admin logic remains hard to unit test | Extract admin approval/query services selectively. |
| Transit backend | Confirmed implemented | `satoidc/satoidc/auth/oidc_signing_backends.py` | Operator setup still hard | Add runbook. |
| Fixed admin limits | Confirmed active | `dashboard.py` `.limit(10)` | Admin views truncate silently | Add pagination. |
| Structured logs | Confirmed gap | `logging.getLogger` usage, no JSON logging baseline | Harder production diagnosis | Add event taxonomy and JSON output. |
| Test task coverage | Confirmed | `satoidc/pyproject.toml` | Load/conformance evidence still incomplete | Publish load and conformance reports. |
