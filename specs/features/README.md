# Feature Specs

Create one Markdown file per feature or meaningful behavior change.

Recommended filename format:

```text
YYYY-MM-DD-short-feature-name.md
```

Start from `../_template.md` and keep each spec focused enough to review with the code change it drives.

## Current Feature Specs

- [LNURL Registration Valid User Creation](lnurl-registration-valid-user/spec.md): implemented spec for using `satoshi` as the default LNURL registration nickname.
- [Reverse Proxy Authentication Rate Limiting](auth-rate-limiting/spec.md): approved spec for delegating public auth, recovery, and LNURL callback throttling to NGINX, Traefik, or equivalent reverse proxies.
- [Admin Dashboard Safety And Scale](admin-dashboard-safety-scale/spec.md): review spec for destructive action confirmation and server-side dashboard pagination.
- [Setup Wizard Complete Specification](setup-wizard/spec.md): canonical review spec for guided and non-interactive setup, `_FILE` secrets, admin bootstrap, setup state, and reconfiguration.
- [Operator Runbooks](operator-runbooks/spec.md): draft spec for backup, restore, upgrade, reverse proxy, email, and Transit operations docs.
- [OIDC Conformance Evidence](oidc-conformance/spec.md): draft spec for documenting OpenID Provider conformance targets and results.
- [Operational Observability Baseline](operational-observability/spec.md): draft spec for structured logs, audit/log separation, and operator-visible failure events.
- [Automated Testing Baseline](quality-testing/spec.md): draft umbrella spec for default pytest, browser e2e, container integration, and load testing strategy.
- [Pytest And Test Extensions](quality-testing/pytest-extensions.md): draft spec for pytest, markers, coverage, async fixtures, factories, and deterministic time helpers.
- [Hypothesis Property Tests](quality-testing/hypothesis-property.md): draft spec for property-based/fuzzy tests over validation, redirects, tokens, LNURL inputs, and OIDC claim invariants.
- [Tavern API Security Tests](quality-testing/tavern-api-security.md): implemented spec for declarative YAML API security tests over route boundaries, OAuth/OIDC negative cases, and secret-free responses.
- [Playwright UI Tests](quality-testing/playwright-ui.md): draft spec for browser e2e coverage of NiceGUI and OAuth flows.
- [Locust Load Tests](quality-testing/locust-load.md): draft spec for repeatable load testing scenarios and commands.
- [Testcontainers Integration Tests](quality-testing/testcontainers-integration.md): draft spec for PostgreSQL-backed integration tests with disposable containers.
- [OIDC Key Rotation](oidc-key-rotation/spec.md): implemented specification for generation, activation, JWKS publication, retention, retirement, and audit of OIDC signing keys.
- [Permission Requests](permission-requests/spec.md): implemented specification for developer access requests, admin notifications, approval/denial workflow, and admin dashboard improvements.

## Superseded Feature Specs

- [Application Setup Bootstrap](application-setup/spec.md): superseded
  historical bootstrap slice. Future setup work belongs in
  [Setup Wizard Complete Specification](setup-wizard/spec.md).

Keep this list aligned with [../index.md](../index.md).
