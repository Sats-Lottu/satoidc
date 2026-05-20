# Spec: Operational Observability Baseline

## Status

- Status: draft
- Owner: TBD
- Created: 2026-05-16
- Updated: 2026-05-20
- Related code:
  - `satoidc/satoidc/auth/`
  - `satoidc/satoidc/routes/`
  - `satoidc/satoidc/models/`
- Related specs:
  - `specs/flows/deployment.md`
  - `specs/features/oidc-key-rotation/spec.md`
  - `specs/features/auth-rate-limiting/spec.md`
  - `specs/contracts/security-session.md`
  - `specs/features/operator-runbooks/spec.md`
  - `specs/features/operational-observability/metrics-baseline.md`

## Intent

Establish a minimal observability baseline for security-relevant and
operationally relevant behavior without turning the beta app into a heavy
telemetry platform.

## Context

SatOIDC already audits OIDC key lifecycle events in the database and uses
standard Python logging in several auth and route modules. Some UI and business
failures are currently surfaced only through `ui.notify`, which is not enough
for production operations, incident review, or container log ingestion.

The PRD and technical readiness report separate observability into four
concerns:

- database audit events for durable product history;
- structured application logs for container stdout ingestion;
- metrics for Prometheus-compatible systems if/when implemented;
- tracing as future optional OpenTelemetry work.

## Scope

In scope:

- Standardize Python logging for important authentication, authorization,
  token, LNURL, and key-management events.
- Ensure logs are useful from stdout in container deployments.
- Define an event taxonomy for auth failures, admin mutations, token failures,
  email delivery failures, Transit failures, and rate-limit decisions.
- Avoid logging secrets, tokens, private keys, passwords, or full sensitive
  payloads.
- Keep database audit events where they are part of product behavior.

Out of scope:

- Mandatory OpenTelemetry tracing in the first pass.
- External SaaS log vendor integration.
- Prometheus metrics exporter implementation.
- Logging every UI notification.

## Rules

- Logs must be structured enough to filter by event name, component, outcome,
  and correlation fields where available.
- JSON logs are a product requirement for self-hosted operations, but
  implementation may use standard `logging` with a JSON formatter, `structlog`,
  or another narrow adapter.
- Prometheus must be treated as a metrics target, not as a log ingestion target.
- Metrics names, labels, cardinality limits, and `/metrics` access decisions
  are defined in `metrics-baseline.md`.
- Security failures should log the reason class without leaking credentials or
  token contents.
- User-facing notifications remain concise and do not replace server logs.
- Audit events and operational logs are complementary, not interchangeable.

## Candidate Events

- Middleware denies or redirects protected route access.
- Page-level permission denial.
- OAuth token issuance failure.
- OIDC signing backend failure.
- LNURL callback invalid signature, expired challenge, or consumed challenge.
- Profile and dashboard mutation failures.
- Admin key rotation and permission approval failures.
- Rate-limit allow/deny decisions at an aggregate event level.
- Email token delivery or send failures.

## Acceptance Criteria

- Given a protected route is requested without a session, then a debug or info
  log can identify the redirect without exposing secrets.
- Given OAuth token issuance fails unexpectedly, then an error log includes the
  component and sanitized failure class.
- Given an OIDC signing backend fails, then the failure is logged and token
  issuance fails closed.
- Given profile or dashboard mutations fail, then operators can see a sanitized
  log entry in addition to the UI notification.
- Given tests capture logs, then sensitive fields such as passwords, tokens,
  private JWKs, and client secrets are absent.
- Given the app runs in Docker, then selected auth and admin events are visible
  as structured stdout records.

## Test Plan

- Unit: log-sanitization helpers if introduced.
- Integration: selected auth/OIDC failure paths with `caplog`.
- Security/regression: assertions that sensitive values do not appear in logs.
- Manual/operations: run app in Docker and confirm stdout contains readable
  records for selected events.

## Implementation Notes

Start with standard-library `logging` and consistent event fields unless a JSON
logging dependency materially reduces complexity. `structlog` is acceptable but
not required. OpenTelemetry tracing remains future work.

## Traceability

- Code:
  - `satoidc/satoidc/auth/middleware.py`
  - `satoidc/satoidc/auth/client_management.py`
  - `satoidc/satoidc/auth/oidc_keys.py`
  - `satoidc/satoidc/auth/permissions.py`
  - `satoidc/satoidc/routes/lnurl_auth.py`
  - `satoidc/satoidc/routes/oauth2.py`
- Tests:
  - `satoidc/tests/conftest.py`
  - `satoidc/tests/test_security.py`
  - `satoidc/tests/test_create_client.py`
  - `satoidc/tests/test_lnurl_auth.py`
  - `satoidc/tests/test_oauth_routes.py`
  - `satoidc/tests/test_oidc_key_rotation.py`
  - `satoidc/tests/test_permission_requests.py`
- Docs: `docs/priority-execution-backlog.md`
- Decisions: `agent-memory/decisions.md`
