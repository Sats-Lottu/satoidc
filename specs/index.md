# Specs Index

Use this index to track active and historical specs.

| Spec | Status | Area | Last Updated |
| --- | --- | --- | --- |
| [Authlib FastAPI Adapter](contracts/authlib-adapter.md) | draft | OAuth/OIDC | 2026-05-17 |
| [Database Contract](contracts/database.md) | draft | Persistence | 2026-05-17 |
| [Runtime Configuration Contract](contracts/runtime-config.md) | draft | Runtime/Configuration | 2026-05-18 |
| [Security And Session Contract](contracts/security-session.md) | draft | Auth/Security | 2026-05-13 |
| [Permission Requests](features/permission-requests/spec.md) | implemented | Auth/UI/Admin | 2026-05-13 |
| [Email Verification And Account Recovery](features/email-verification/spec.md) | implemented | Auth/Security | 2026-05-17 |
| [Application Setup Bootstrap](features/application-setup/spec.md) | superseded | Bootstrap/Operations | 2026-05-18 |
| [Setup Wizard Complete Specification](features/setup-wizard/spec.md) | review | Bootstrap/Operations/UI | 2026-05-18 |
| [Public Route Boundary Hardening](features/public-route-boundary/spec.md) | implemented | Auth/Security | 2026-05-16 |
| [External OIDC Signing Backend](features/external-signing-backend/spec.md) | implemented | OAuth/OIDC Security | 2026-05-17 |
| [Route Service Extraction](features/route-service-extraction/spec.md) | implemented | Auth/UI/Persistence | 2026-05-18 |
| [LNURL Registration Valid User Creation](features/lnurl-registration-valid-user/spec.md) | implemented | LNURL/Auth/Persistence | 2026-05-18 |
| [Reverse Proxy Authentication Rate Limiting](features/auth-rate-limiting/spec.md) | approved | Auth/Security/Operations | 2026-05-18 |
| [Admin Dashboard Safety And Scale](features/admin-dashboard-safety-scale/spec.md) | review | Admin/UI | 2026-05-18 |
| [Operator Runbooks](features/operator-runbooks/spec.md) | draft | Operations/Docs | 2026-05-18 |
| [OIDC Conformance Evidence](features/oidc-conformance/spec.md) | active | OAuth/OIDC/Compliance | 2026-05-20 |
| [Operational Observability Baseline](features/operational-observability/spec.md) | draft | Operations/Security | 2026-05-18 |
| [Prometheus-Compatible Metrics Baseline](features/operational-observability/metrics-baseline.md) | draft | Operations/Metrics | 2026-05-20 |
| [Automated Testing Baseline](features/quality-testing/spec.md) | draft | Testing/Quality | 2026-05-17 |
| [Pytest And Test Extensions](features/quality-testing/pytest-extensions.md) | draft | Testing/Quality | 2026-05-17 |
| [Hypothesis Property Tests](features/quality-testing/hypothesis-property.md) | draft | Testing/Quality | 2026-05-17 |
| [Tavern API Security Tests](features/quality-testing/tavern-api-security.md) | implemented | Testing/Security | 2026-05-17 |
| [Playwright UI Tests](features/quality-testing/playwright-ui.md) | draft | Testing/UI | 2026-05-17 |
| [Locust Load Tests](features/quality-testing/locust-load.md) | draft | Testing/Performance | 2026-05-17 |
| [Testcontainers Integration Tests](features/quality-testing/testcontainers-integration.md) | draft | Testing/Integration | 2026-05-17 |
| [OIDC Key Rotation](features/oidc-key-rotation/spec.md) | implemented | OAuth/OIDC Security | 2026-05-18 |
| [OIDC Contract](contracts/oidc.md) | draft | OAuth/OIDC | 2026-05-06 |
| [Authorization Code Flow](flows/authorization-code.md) | implemented | OAuth/OIDC | 2026-05-15 |
| [OAuth Client Registration Flow](flows/client-registration.md) | implemented | OAuth/UI | 2026-05-18 |
| [Deployment Flow](flows/deployment.md) | draft | Operations | 2026-05-17 |
| [Login Flow](flows/login.md) | draft | Auth/UI | 2026-05-06 |
| [Registration Flow](flows/registration.md) | draft | Auth/UI | 2026-05-08 |
| [Page Security Flow](flows/page-security.md) | draft | Auth/UI | 2026-05-08 |
| [Home And Client Console Flow](flows/home-and-client-console.md) | draft | Auth/UI | 2026-05-13 |
| [Profile Flow](flows/profile.md) | implemented | Auth/UI | 2026-05-15 |
| [LNURL-auth Flow](flows/lnurl-auth.md) | draft | LNURL/Auth | 2026-05-18 |
| [Relying-Party Example Flows](flows/relying-party-examples.md) | draft | Examples/OIDC | 2026-05-13 |
| [Setup Wizard Flow](flows/setup-wizard.md) | draft | Bootstrap/Auth/UI | 2026-05-18 |
| [OAuth Token Lifecycle Flow](flows/token-lifecycle.md) | draft | OAuth/OIDC | 2026-05-17 |
| [Setup Wizard Spec Consolidation](decisions/2026-05-18-setup-wizard-spec-consolidation.md) | implemented | Decision/Specs | 2026-05-18 |
| [Repository Language Policy](decisions/2026-05-18-documentation-language-policy.md) | implemented | Decision/Docs | 2026-05-18 |

## Product Backlog Traceability

Resolved PRD backlog items that remain documented for history:

- `P0-01` maps to
  [LNURL Registration Valid User Creation](features/lnurl-registration-valid-user/spec.md),
  which is implemented. Keep future work limited to regression coverage unless a
  new LNURL registration bug is found.

Open PRD backlog items with active specs:

- `P0-02` maps to
  [Reverse Proxy Authentication Rate Limiting](features/auth-rate-limiting/spec.md).
- `P1-01` and the pagination part of `P2-01` map to
  [Admin Dashboard Safety And Scale](features/admin-dashboard-safety-scale/spec.md).
- `P1-02` maps to
  [Operational Observability Baseline](features/operational-observability/spec.md).
- `P1-03` maps to [Operator Runbooks](features/operator-runbooks/spec.md).
- `P2-02` maps to [Locust Load Tests](features/quality-testing/locust-load.md)
  and [OAuth Token Lifecycle Flow](flows/token-lifecycle.md).
- `P3-01` maps to [OIDC Conformance Evidence](features/oidc-conformance/spec.md).

## Status Values

- `draft`: being shaped; not ready for implementation.
- `review`: ready for product/engineering review.
- `approved`: ready for implementation.
- `implemented`: code and tests satisfy the spec.
- `superseded`: replaced by another spec or decision.
