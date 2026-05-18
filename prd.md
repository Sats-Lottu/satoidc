# SatOIDC Product Requirements Document

Updated: 2026-05-18

## 1. Executive Summary

SatOIDC is a self-hosted OpenID Connect Provider built with Python, FastAPI,
NiceGUI, Authlib, SQLAlchemy, and Alembic. It combines conventional OAuth2/OIDC
flows with Bitcoin/Lightning LNURL-auth so small teams, communities, and
sovereign operators can run their own identity provider without adopting a large
enterprise IAM stack.

The current product is a usable beta. Core OIDC, PKCE, refresh tokens, user
profile management, email verification/recovery, client management, Docker
Compose, PostgreSQL integration tests, and OpenBao/Vault-compatible Transit
signing are implemented. The next product goal is to make SatOIDC dependable as
a self-hosted product: safer public endpoints, clearer operations, stronger
admin UX, documented recovery paths, measurable performance limits, and OIDC
conformance evidence.

## 2. Product Vision

SatOIDC should become a compact, auditable, self-hosted identity provider for
Bitcoin-first applications that still need standard OIDC interoperability.

- **Positioning:** a lightweight OIDC Provider for operators who want Docker
  Compose deployment, explicit configuration, and Lightning-native login.
- **Differentiator:** first-class LNURL-auth plus regular OIDC relying-party
  compatibility.
- **Operating model:** one self-hosted SatOIDC instance acts as the identity
  provider for one organization, project, or community.
- **Limit:** SatOIDC should not try to become a broad enterprise IAM suite before
  the self-hosted OIDC + LNURL product is stable.

## 3. Target Personas

- **Self-hosted operator:** installs, configures, backs up, upgrades, and
  troubleshoots SatOIDC. Needs runbooks, clear logs, safe migrations, and
  predictable recovery.
- **Relying-party developer:** creates OAuth2/OIDC clients, configures redirect
  URIs, validates scopes, and integrates with standard OIDC libraries.
- **Root/admin user:** approves developer access, manages users and clients,
  rotates signing keys, and handles operational incidents.
- **End user:** registers, logs in with password or Lightning wallet, verifies
  email, recovers password, and manages profile/wallet links.
- **Open-source contributor:** needs a clear architecture, focused tests, and
  documented conventions for auth, persistence, migrations, and UI changes.

## 4. Problem Statement

SatOIDC solves:

- Running a small OIDC Provider without adopting heavyweight IAM platforms.
- Adding LNURL-auth to OIDC relying parties through a standard provider boundary.
- Managing OAuth2 clients, user profile flows, and signing keys from one
  self-hosted application.

Remaining product gaps:

- Rate limiting is delegated to the reverse proxy layer for production, so
  direct exposure without NGINX, Traefik, or equivalent throttling is not a
  supported hardened deployment shape.
- LNURL registration uses the default nickname `satoshi` when no nickname is
  supplied, and this behavior needs regression coverage.
- Operators lack production runbooks for backup, restore, upgrade, reverse proxy
  setup, and incident response.
- Logs and metrics are not yet packaged as an operator-facing observability
  baseline.
- Admin dashboards use fixed query limits and need server-side pagination before
  they scale beyond small instances.
- OIDC conformance has focused tests but no OpenID Foundation Basic OP evidence.

## 5. Product Principles

- **Secure by default:** production mode rejects placeholder secrets and uses
  hardened cookie behavior.
- **Protocol correctness:** OIDC/OAuth2 behavior should stay compatible with
  standard relying-party libraries.
- **Explicit configuration:** runtime behavior is configured through environment
  variables and should fail clearly when invalid.
- **Recoverability:** local and production data recovery paths must be documented
  and tested.
- **Observable operations:** auth failures, admin actions, token behavior, and
  operational errors should be diagnosable from logs, metrics, and audit data.
- **Admin safety:** destructive actions should require deliberate confirmation.
- **Responsive operations UI:** dashboards should be dense, scannable, and usable
  on desktop, tablet, and mobile without behaving like a marketing page.

## 6. Current Product Inventory

| Area | Current Status | Evidence | Product Gap |
| --- | --- | --- | --- |
| Docker Compose setup | Implemented | `compose.yaml`, `.env.example`, `satoidc/entrypoint.sh` | Needs operator runbook for upgrade/restore. |
| Runtime configuration | Implemented | `satoidc/satoidc/settings.py` | Needs full operator-facing config reference. |
| SQLite/PostgreSQL support | Implemented and tested | `docs/database-support-matrix.md`, `poetry run task test_integration` | Production backup/restore docs are missing. |
| Alembic migrations | Implemented | `satoidc/migrations/versions/` | Migration troubleshooting exists for local SQLite; production runbook missing. |
| OIDC authorization code + PKCE | Implemented | `satoidc/satoidc/routes/oauth2.py`, tests | Needs OpenID Foundation conformance evidence. |
| Refresh, introspection, revocation | Implemented | `satoidc/satoidc/routes/oauth2.py`, tests | Refresh-token revocation needs broader e2e coverage. |
| LNURL-auth | Implemented | `satoidc/satoidc/routes/lnurl_auth.py` | Uses default nickname `satoshi` for wallet-created users. |
| Email verification/recovery | Implemented | `satoidc/satoidc/services/email_tokens.py`, `satoidc/satoidc/services/email_delivery.py` | Operator docs for SMTP modes should be expanded. |
| OIDC signing keys | Implemented | `satoidc/satoidc/auth/oidc_keys.py` | Transit deployment docs should be operator-focused. |
| OpenBao/Vault Transit signing | Implemented | `satoidc/satoidc/auth/oidc_signing_backends.py`, integration tests | Needs deployment runbook and failure-mode docs. |
| Profile/client service layer | Partially implemented | `satoidc/satoidc/services/profile.py`, `satoidc/satoidc/services/oauth_clients.py` | `dashboard.py` still contains admin query and commit logic. |
| Admin/developer dashboards | Implemented for small instances | `satoidc/satoidc/routes/dashboard.py` | Fixed limits, destructive action friction, and pagination need work. |
| Reverse-proxy rate limiting | Delegated operational requirement | `docs/operations/reverse-proxy.md` | Hardened deployments must configure NGINX, Traefik, or equivalent edge throttling. |
| Observability | Partial | `logging.getLogger`, `OidcSigningKeyAuditEvent` | Needs structured logs, metrics plan, and operator docs. |

## 7. Functional Requirements

| ID   | Requirement                                                | Priority | Current Status       | Evidence                                           | Gap                                             | Acceptance Criteria                                                                   |
| ---- | ---------------------------------------------------------- | -------- | -------------------- | -------------------------------------------------- | ----------------------------------------------- | ------------------------------------------------------------------------------------- |
| FR01 | Install with Docker Compose                                | P0       | Implemented          | `compose.yaml`, `.env.example`                     | Runbook missing                                 | A new operator can deploy using documented commands and verify health.                |
| FR02 | Bootstrap root account                                     | P0       | Implemented          | setup wizard code and docs                         | Recovery path unclear                           | Empty deployments require root creation before normal operation.                      |
| FR03 | Support SQLite for local use and PostgreSQL for production | P0       | Implemented          | `docs/database-support-matrix.md`                  | Backup docs missing                             | Invalid async/sync URL pairings fail early.                                           |
| FR04 | Apply Alembic migrations                                   | P0       | Implemented          | `satoidc/entrypoint.sh`, migrations                | Production rollback/runbook missing             | Container startup applies `alembic upgrade head` and failures are visible.            |
| FR05 | Issue OIDC authorization-code tokens with PKCE             | P0       | Implemented          | `routes/oauth2.py`, tests                          | Conformance not certified                       | Standard relying parties complete the authorization-code flow.                        |
| FR06 | Support refresh, revocation, introspection, userinfo       | P0       | Implemented          | `routes/oauth2.py`, tests                          | Needs broader e2e revocation coverage           | Token lifecycle behavior is covered by unit/integration/e2e tests.                    |
| FR07 | Register and login with password                           | P0       | Implemented          | `routes/login.py`, `routes/register.py`            | Reverse-proxy throttling must be deployed       | Brute-force attempts are throttled at the edge.                                       |
| FR08 | Register/login/link with LNURL-auth                        | P0       | Implemented          | `routes/lnurl_auth.py`                             | Keep default nickname regression coverage       | LNURL registration uses `satoshi` when no nickname is supplied.                       |
| FR09 | Verify email and recover password                          | P0       | Implemented          | `services/email_tokens.py`, recovery routes        | SMTP docs need expansion                        | Tokens are hashed, single-use, expiring, and rate-limited by request interval.        |
| FR10 | Manage OAuth2 clients                                      | P1       | Implemented          | `services/oauth_clients.py`, `routes/dashboard.py` | Destructive action confirmation missing         | Client delete/secret rotation flows require deliberate confirmation.                  |
| FR11 | Approve developer permission requests                      | P1       | Implemented          | `routes/dashboard.py`, permission services         | Pagination and admin audit UX need work         | Admins can find, review, approve, deny, and audit requests at scale.                  |
| FR12 | Sign ID Tokens with database or Transit backend            | P1       | Implemented          | `auth/oidc_signing_backends.py`                    | Operator docs for Transit failure modes missing | Operators can switch backend through env vars and validate JWKS/token signing.        |
| FR13 | Provide reverse-proxy rate limiting guidance               | P1       | Documented           | `docs/operations/reverse-proxy.md`                 | Operators must apply it in production           | NGINX and Traefik examples are available and linked from the docs index.              |
| FR14 | Provide structured operational logs                        | P1       | Missing              | current `logging.getLogger` use                    | No JSON log baseline                            | Auth failures and admin mutations emit structured logs to stdout.                     |
| FR15 | Provide operator runbooks                                  | P1       | Missing              | docs gap                                           | No production backup/restore guide              | Runbooks cover backup, restore, upgrade, reverse proxy, SMTP, Transit, and incidents. |
| FR16 | Support responsive admin UX                                | P2       | Partial              | `DESIGN.md`, `ui_components.py`                    | Table pagination and a11y verification missing  | Dashboards work on desktop/tablet/mobile with no horizontal overflow.                 |
| FR17 | Validate OIDC Basic OP conformance                         | P3       | Not confirmed        | no conformance task in `pyproject.toml`            | Certification evidence missing                  | Basic OP test results are documented or automated.                                    |

## 8. Non-Functional Requirements

| ID | Requirement | Target |
| --- | --- | --- |
| NFR01 | Security | Public auth endpoints must be rate-limited and produce useful failure logs. |
| NFR02 | Reliability | Migration and startup failures must fail clearly without corrupting data. |
| NFR03 | Observability | Logs should be JSON-friendly for stdout/Loki/ELK/Datadog/Splunk; metrics should be exposed separately for Prometheus-compatible systems when implemented. |
| NFR04 | Performance | `/oauth/token` threadpool limits must be measured with `poetry run task test_load` or an equivalent load profile before publishing capacity guidance. |
| NFR05 | Accessibility | User-facing UI should target WCAG 2.2 AA for contrast, keyboard focus, labels, and dialog behavior. |
| NFR06 | Responsiveness | Core flows must work across desktop, tablet, and mobile/touch layouts. |
| NFR07 | Maintainability | Auth, token, persistence, and migration changes require focused tests. |

## 9. Security Requirements

| ID | Requirement | Status | Acceptance Criteria |
| --- | --- | --- | --- |
| SR01 | Rate-limit login, registration, recovery, and LNURL callback surfaces | Delegated to reverse proxy | NGINX, Traefik, or equivalent edge throttling protects public auth routes before they reach SatOIDC. |
| SR02 | Prevent LNURL registration invalid user rows | Implemented | LNURL registration uses `satoshi` when no nickname is supplied; regression test covers the path. |
| SR03 | Keep redirect targets local | Implemented | `safe_redirect` rejects absolute, scheme-relative, and control-character targets. |
| SR04 | Harden production secrets | Implemented | Production startup rejects placeholder secrets. |
| SR05 | Support external signing backend | Implemented | Transit backend signs ID Tokens and publishes usable JWKS metadata. |
| SR06 | Protect destructive admin actions | Missing | Client deletion requires text confirmation and clear warning copy. |
| SR07 | Audit privileged operations | Partial | Key events are audited; admin/client/user mutations need consistent structured audit events. |

## 10. Self-Hosted Readiness

| Capability | Rating | Rationale | Required Improvement |
| --- | --- | --- | --- |
| Install | 4/5 | Compose and env examples exist. | Add operator quick-start with verification steps. |
| Configure | 4/5 | Settings are centralized. | Publish a full env var reference. |
| Bootstrap | 4/5 | Setup wizard exists. | Document root recovery procedure. |
| Migrate | 4/5 | Alembic is integrated. | Add production migration failure runbook. |
| Backup/restore | 2/5 | Underlying DBs support it. | Write and test PostgreSQL/SQLite restore procedures. |
| Observe | 2/5 | Some logs and DB audit events exist. | Add structured logs and metrics guidance. |
| Upgrade | 3/5 | Migrations run, but release process docs are thin. | Add versioned upgrade checklist. |
| Operate behind reverse proxy | 2/5 | Deployment docs exist. | Document proxy headers, TLS, forwarded IP, and rate-limit implications. |

## 11. UX Requirements

SatOIDC UI should follow `DESIGN.md` and product-grade responsive admin UX
patterns from Material Design, Fluent, Apple HIG, Nielsen heuristics, and WCAG.

- **Desktop:** dashboards should prioritize dense, scannable tables and stable
  toolbars rather than hero-style layouts.
- **Tablet/mobile:** navigation must remain touch-friendly; tables should
  collapse, paginate, or use list layouts without horizontal overflow.
- **Forms:** OAuth client forms should use clear option controls for common
  client types and validate redirect URI/scope fields inline.
- **Destructive actions:** delete and secret rotation flows need explicit warning
  copy and confirmation friction.
- **States:** empty, loading, error, disabled, and success states should be
  visible and actionable.
- **Accessibility:** keyboard focus, labels, dialog semantics, contrast, icon
  labels, and QR-code dialog behavior need systematic verification.

## 12. Documentation Requirements

Required docs before a self-hosted MVP label:

- `docs/operations/runbook.md`: backup, restore, upgrade, rollback expectations,
  health checks, and incident response.
- `docs/operations/reverse-proxy.md`: NGINX and Traefik examples, TLS,
  forwarded headers, rate limiting, and IP handling.
- `docs/operations/email.md`: SMTP, console, disabled modes, token TTLs, and
  delivery troubleshooting.
- `docs/operations/transit.md`: OpenBao/Vault Transit setup, required env vars,
  failure modes, and fallback expectations.
- `docs/conformance.md`: OIDC conformance scope, current test evidence, and known
  deviations if any.
- README links to each operator-facing document.

## 13. Release Readiness Checklist

Self-hosted MVP:

- [x] LNURL registration uses `satoshi` when no nickname is supplied.
- [ ] Hardened deployments configure reverse-proxy rate limiting for auth, registration, recovery, and LNURL endpoints.
- [ ] Client deletion requires text confirmation.
- [ ] Operator runbook covers backup, restore, upgrade, and reverse proxy setup.
- [ ] Structured application logs are emitted to stdout.
- [ ] README links to self-hosted operations docs.

Production 1.0:

- [ ] Load-test baseline is documented for `/oauth/token`.
- [ ] Admin dashboards have server-side pagination.
- [ ] OIDC Basic OP conformance results are documented.
- [ ] Accessibility smoke checks cover core user and admin flows.
- [ ] Transit deployment runbook is validated against a fresh environment.

## 14. Product Roadmap

### Phase 0: Immediate Risk Reduction

- Keep LNURL default nickname regression coverage.
- Document and verify reverse-proxy rate limiting for public auth surfaces.
- Add text confirmation for OAuth client deletion.

### Phase 1: Self-Hosted MVP

- Add operator runbooks for backup/restore/upgrade/reverse proxy.
- Add structured JSON logging baseline.
- Expand SMTP and Transit setup documentation.

### Phase 2: Production Hardening

- Add server-side pagination for admin dashboards.
- Measure and document load thresholds.
- Add broader refresh-token revocation e2e coverage.

### Phase 3: OIDC Conformance

- Run OpenID Foundation Basic OP tests.
- Document conformance results and known deviations.
- Add relying-party integration examples for common stacks.

### Phase 4: Operator Experience

- Add metrics guidance or exporter.
- Improve admin audit views.
- Consider admin APIs only after the UI and service boundaries are stable.

## 15. Prioritized Product Backlog

| ID | Title | Type | Priority | Effort | Impact | Acceptance Criteria |
| --- | --- | --- | --- | --- | --- | --- |
| P0-01 | Keep LNURL default nickname valid | bugfix | P0 | S | High | LNURL registration uses `satoshi` and regression tests pass. |
| P0-02 | Document reverse-proxy auth rate limiting | security | P0 | S | High | NGINX and Traefik examples cover login/register/recovery/LNURL throttling. |
| P1-01 | Add destructive action confirmation | uiux | P1 | S | Medium | Client deletion requires typing the client identifier/name. |
| P1-02 | Add structured logging baseline | ops | P1 | M | High | Auth failures and admin mutations emit structured JSON logs. |
| P1-03 | Write operator runbook | docs | P1 | M | High | Backup/restore/upgrade/reverse-proxy procedures are documented and linked. |
| P2-01 | Add dashboard pagination | uiux | P2 | M | Medium | Admin lists expose server-side pagination controls. |
| P2-02 | Publish load baseline | tests | P2 | M | Medium | `test_load` or equivalent produces documented capacity guidance. |
| P3-01 | Run OIDC conformance | compliance | P3 | L | High | Basic OP results are captured in `docs/conformance.md`. |

## 16. Out Of Scope

- Enterprise SAML/LDAP identity brokering.
- Multi-tenant organization isolation.
- Replacing NiceGUI with a separate SPA frontend before product readiness gaps
  are closed.
- Rewriting Authlib integration before load data shows the current boundary is
  insufficient.

## 17. Open Questions

- Should LNURL `auth` be removed until a stateless authorization contract exists?
- Should local database files be replaced by seed/setup workflows for repeatable
  development?
- What production load target should SatOIDC publish for small VPS deployments?
- Which OIDC relying-party stacks should be part of the compatibility matrix?

## 18. Working Assumptions

- LNURL `auth` should remain optional and marked as architecturally under
  review until there is a clear stateless authorization contract.
- Local database files should eventually be replaceable by repeatable seed/setup
  workflows for deterministic development resets.
- The first published load target should be conservative and tied to
  reproducible benchmarks with explicit CPU, RAM, database, and user/auth-flow
  assumptions.
- The initial OIDC compatibility matrix should cover practical relying-party
  stacks such as FastAPI/Authlib clients, Django, Auth.js/NextAuth, Grafana,
  Gitea, MinIO, oauth2-proxy, and reverse-proxy integrations.

## 19. References

- Atlassian product requirements guidance: https://www.atlassian.com/agile/requirements
- OpenID Connect certification: https://openid.net/certification/
- OpenID Connect OP testing: https://openid.net/certification/connect_op_testing/
- OAuth 2.0 Security Best Current Practice, RFC 9700: https://www.rfc-editor.org/rfc/rfc9700
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- Twelve-Factor App: https://12factor.net/
- OpenTelemetry observability primer: https://opentelemetry.io/docs/concepts/observability-primer/
- WCAG 2.2: https://www.w3.org/TR/WCAG22/
- Nielsen Norman usability heuristics: https://www.nngroup.com/articles/ten-usability-heuristics/
- Microsoft Fluent 2 Layout: https://fluent2.microsoft.design/layout
- Apple Human Interface Guidelines: https://developer.apple.com/design/human-interface-guidelines
- Material Design 3: https://m3.material.io/
