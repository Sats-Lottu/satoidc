# Spec: Prometheus-Compatible Metrics Baseline

## Status

- Status: draft
- Owner: project maintainers
- Created: 2026-05-20
- Updated: 2026-05-20
- Related specs:
  - `specs/features/operational-observability/spec.md`
  - `specs/contracts/security-session.md`
  - `specs/flows/token-lifecycle.md`
  - `specs/flows/lnurl-auth.md`

## Intent

Define a privacy-preserving Prometheus-compatible metrics baseline before
adding a metrics exporter. This spec names the first metrics, stable labels,
and forbidden dimensions so implementation can avoid high-cardinality or
sensitive data leaks.

## Rules

- Metrics must never include user IDs, emails, login names, wallet public keys,
  client secrets, raw client IDs, IP addresses, tokens, authorization codes,
  session IDs, redirect URIs, or exception messages as labels.
- Labels must come from bounded enums or low-cardinality route groups.
- Metrics count behavior and latency, not payload contents.
- Logs remain the source for sanitized troubleshooting detail; metrics are for
  aggregate health, alerting, and dashboards.
- A future `/metrics` endpoint must be protected by deployment-level controls
  or an admin-only application guard. Public unauthenticated exposure is out of
  scope.

## Allowed Labels

| Label | Allowed values or source | Notes |
| --- | --- | --- |
| `component` | bounded component names such as `oauth2`, `lnurl_auth`, `email_delivery`, `oidc_keys`, `setup_bootstrap` | Must match structured log component taxonomy where possible. |
| `outcome` | `success`, `failed`, `rejected`, `skipped` | Keep values stable and generic. |
| `reason` | bounded reason classes such as `invalid_csrf`, `invalid_grant`, `bad_signature`, `disabled`, `transit_unavailable` | No free-form exception messages. |
| `grant_type` | `authorization_code`, `refresh_token`, `unknown` | From OAuth request type, not token contents. |
| `token_type` | `access_token`, `refresh_token`, `unknown` | Only for revocation/introspection aggregate counters. |
| `action` | `register`, `login`, `link`, `unknown` | LNURL action enum only. |
| `method` | HTTP method | Standard HTTP metric label. |
| `route_group` | bounded groups such as `public_metadata`, `oauth_token`, `oauth_userinfo`, `lnurl_callback`, `setup`, `admin` | Do not use raw full paths with dynamic or query values. |

## Forbidden Labels

- `user_id`
- `email`
- `login`
- `nickname`
- `lnurl_pubkey`
- `client_id`
- `client_secret`
- `ip`
- `user_agent`
- `access_token`
- `refresh_token`
- `authorization_code`
- `redirect_uri`
- `state`
- `nonce`
- `exception`
- raw request path or query string

## Proposed Metrics

| Metric | Type | Labels | Description |
| --- | --- | --- | --- |
| `satoidc_http_requests_total` | counter | `method`, `route_group`, `outcome` | Aggregate HTTP request outcomes by bounded route group. |
| `satoidc_http_request_duration_seconds` | histogram | `method`, `route_group` | Request latency by bounded route group. |
| `satoidc_auth_attempts_total` | counter | `component`, `outcome`, `reason` | Password/session/setup authentication attempts and rejections. |
| `satoidc_oauth_token_requests_total` | counter | `grant_type`, `outcome`, `reason` | Token endpoint requests, including authorization-code and refresh grants. |
| `satoidc_oauth_introspection_requests_total` | counter | `token_type`, `outcome`, `reason` | Introspection outcomes without token values. |
| `satoidc_oauth_revocation_requests_total` | counter | `token_type`, `outcome`, `reason` | Revocation outcomes without token values. |
| `satoidc_lnurl_callbacks_total` | counter | `action`, `outcome`, `reason` | LNURL callback validation and action outcomes. |
| `satoidc_email_delivery_total` | counter | `outcome`, `reason` | Email delivery attempts, skipped delivery, and send failures. |
| `satoidc_oidc_signing_total` | counter | `backend`, `outcome`, `reason` | ID token signing attempts and signing backend failures. |
| `satoidc_admin_mutations_total` | counter | `component`, `outcome`, `reason` | Admin/developer dashboard mutations such as permission decisions, client disable, deletion, and secret rotation. |
| `satoidc_setup_bootstrap_total` | counter | `outcome`, `reason` | Setup/root bootstrap attempts and blocked states. |

## Histogram Defaults

Start with conservative latency buckets for HTTP and token operations:

```text
0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5
```

Do not create per-user, per-client, or per-issuer histograms.

## `/metrics` Access Decision

Initial implementation should prefer deployment-level protection:

- bind metrics only to an internal interface, sidecar, or private network; or
- protect `/metrics` at the reverse proxy with network allowlists and TLS.

If app-level protection is implemented, require `ROOT` or `ADMIN` permission
and document how Prometheus authenticates. Do not expose metrics publicly by
default.

## Acceptance Criteria

- Given metrics are implemented, labels are limited to the allowed list above.
- Given a secret or token value appears in request data, it is never emitted as
  a metric label or sample value.
- Given `/metrics` is enabled, access controls are documented before
  deployment.
- Given a new auth/OIDC/LNURL metric is added, it names a bounded `reason`
  enum and has a privacy review.
