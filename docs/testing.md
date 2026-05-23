# Testing Strategy

SatOIDC uses pytest as the main test runner and separates local, generated,
browser, container, and load checks through explicit `taskipy` commands.

## Local Default Suite

Use the default suite for normal development:

```bash
cd satoidc
poetry run task test
```

This command runs fast pytest, route, service, model, protocol, setup, and API
security smoke tests. It excludes browser e2e, container-backed integration,
property, load, and slow tests. It records terminal coverage through
`pytest-cov` and updates the HTML coverage report through the Taskipy
`post_test` hook.

Regenerate the HTML coverage report explicitly when needed:

```bash
cd satoidc
poetry run task coverage_html
```

## Focused Suites

- `poetry run task test_unit`: same fast boundary as the default local suite.
- `poetry run task test_property`: Hypothesis property tests excluding
  `property_slow`, without coverage reporting.
- `poetry run task test_api_security`: Tavern/Python API security smoke tests,
  without coverage reporting.
- `poetry run task test_integration`: Docker/Testcontainers integration tests
  that exclude `load` tests and run without coverage reporting.
- `poetry run task test_e2e`: Playwright browser UI and OAuth flow tests.
- `poetry run task test_all`: complete non-load, non-slow verification when
  local browser and container prerequisites are available.
- `poetry run task test_load`: headless Locust smoke against a running app.

Focused commands use `--no-cov` so a legitimate subset cannot fail the global
100% coverage gate. The coverage gate belongs to `poetry run task test`, which
is the measured default suite and refreshes the HTML report through
`post_test`.

## Testcontainers Integration Baseline

Container-backed tests live under `satoidc/tests/integration/` and share
fixtures from `satoidc/tests/integration/conftest.py`.

Shared fixtures cover:

- PostgreSQL 16 URLs created by Testcontainers.
- Alembic-migrated PostgreSQL databases.
- A live SatOIDC app bound to a free local port and wired to PostgreSQL for
  async route sessions and Authlib sync sessions.
- Mailpit SMTP/API capture for verification and recovery email delivery.
- OpenBao dev server with the Transit engine enabled for Vault-compatible OIDC
  signing tests.

Prefer these fixtures for new operation-like tests before adding one-off
container setup. Add new shared fixtures when a real dependency appears in more
than one test or when setup details would otherwise obscure the behavior under
test.

## CI Test Policy

CI runs the checks that are high-signal for stability and security without
running load tests:

- `poetry run task lint`
- `poetry run task test`
- `poetry run task test_property`
- `poetry run task test_api_security`
- `poetry run task test_integration`
- Docker image build

OIDC conformance remains evidence-driven and is tracked separately from this CI
baseline until the external conformance run is automated.

## Coverage Focus

The default measured suite is a 100% line coverage gate. `pyproject.toml`
sets `coverage report --fail-under=100`, so `poetry run task test` must fail
when measured line coverage drops below 100%. Do not lower this threshold to
merge AI-assisted work; instead add focused tests or refactor the code so the
behavior can be tested directly.

Keep new coverage close to the risk being tested. Prefer service-level tests
for validation, persistence, email, signing, token, and runtime-setting logic.
Use route tests for HTTP status, redirect, and enumeration-resistance
contracts. Use e2e tests for browser rendering, NiceGUI behavior, and complete
redirect flows.

The 2026-05-23 test-suite cleanup restored the default measured coverage from
93% to 100% by adding focused tests for:

- Runtime setting validation, decoding, persistence, and env alias lookup.
- Email delivery modes without real SMTP network access.
- Recovery route redirects and generic password-reset responses.
- Transit signing helper and client error contracts without Testcontainers.
- OAuth grant ID Token claims and access-token hash helpers.
- Client command validation, setup-state diagnostics, logging sanitization, and
  redirect safety edge cases.

## AI-Assisted TDD Policy

SatOIDC treats AI-assisted production code as untrusted until tests describe and
verify the intended behavior. Any production code generated or substantially
edited with an AI assistant must include tests in the same change.

Use TDD for new behavior:

1. Write or update the failing test that defines the behavior.
2. Implement the smallest code change that makes the test pass.
3. Refactor only after the test is green.
4. Run the smallest relevant suite, then `poetry run task test` before the
   change is considered ready.

For security-sensitive changes, include negative tests and boundary tests for
auth, OIDC/OAuth2, LNURL-auth, secrets, sessions, persistence, redirects, and
token lifetimes. If the code is hard to test, prefer extracting a small service
or helper over relying on broad UI or integration assertions alone.
