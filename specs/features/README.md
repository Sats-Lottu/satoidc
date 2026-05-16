# Feature Specs

- [Permission Requests](permission-requests/spec.md): user requests for developer access, admin notifications, approval/denial workflow, and admin dashboard improvements.

Create one Markdown file per feature or meaningful behavior change.

Recommended filename format:

```text
YYYY-MM-DD-short-feature-name.md
```

Start from `../_template.md` and keep each spec focused enough to review with the code change it drives.

## Current Feature Specs

- [Automated Testing Baseline](quality-testing/spec.md): draft umbrella spec for default pytest, browser e2e, container integration, and load testing strategy.
- [Pytest And Test Extensions](quality-testing/pytest-extensions.md): draft spec for pytest, markers, coverage, async fixtures, factories, and deterministic time helpers.
- [Hypothesis Property Tests](quality-testing/hypothesis-property.md): draft spec for property-based/fuzzy tests over validation, redirects, tokens, LNURL inputs, and OIDC claim invariants.
- [Tavern API Security Tests](quality-testing/tavern-api-security.md): draft spec for declarative YAML API security tests over route boundaries, OAuth/OIDC negative cases, and secret-free responses.
- [Playwright UI Tests](quality-testing/playwright-ui.md): draft spec for browser e2e coverage of NiceGUI and OAuth flows.
- [Locust Load Tests](quality-testing/locust-load.md): draft spec for repeatable load testing scenarios and commands.
- [Testcontainers Integration Tests](quality-testing/testcontainers-integration.md): draft spec for PostgreSQL-backed integration tests with disposable containers.
- [OIDC Key Rotation](oidc-key-rotation/spec.md): draft specification for generation, activation, JWKS publication, retention, retirement, and audit of OIDC signing keys.
- [Permission Requests](permission-requests/spec.md): draft specification for developer access requests, admin notifications, approval/denial workflow, and admin dashboard improvements.

Keep this list aligned with [../index.md](../index.md).
