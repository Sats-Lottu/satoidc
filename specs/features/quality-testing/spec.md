# Spec: Automated Testing Baseline

## Status

- Status: draft
- Owner: project maintainers
- Created: 2026-05-16
- Updated: 2026-05-17
- Related code:
  - `satoidc/pyproject.toml`
  - `satoidc/tests/`
  - `satoidc/tests/e2e/`
- Related specs:
  - `specs/features/quality-testing/pytest-extensions.md`
  - `specs/features/quality-testing/hypothesis-property.md`
  - `specs/features/quality-testing/tavern-api-security.md`
  - `specs/features/quality-testing/playwright-ui.md`
  - `specs/features/quality-testing/locust-load.md`
  - `specs/features/quality-testing/testcontainers-integration.md`

## Intent

Define the minimum automated testing strategy for SatOIDC so protocol behavior,
database compatibility, browser UI flows, and operational performance risks are
verified consistently before changes are considered ready.

## Context

The project already has pytest-based tests, browser e2e tests marked with
`e2e`, and development dependencies for pytest extensions, Playwright, and
Testcontainers. Load testing with Locust is not yet configured.

This spec coordinates the individual testing specs and establishes when each
test tier should run.

## Scope

In scope:

- Unit, integration, route, protocol, browser e2e, container-backed, and load
  test tiers.
- Property-based tests for validation, redirect safety, token lifecycle, LNURL
  parsing, and OIDC claim invariants.
- Declarative API security tests for HTTP contracts and negative endpoint
  behavior.
- Test markers and task commands that make the suites easy to run locally and
  in CI.
- Clear boundaries between default tests, e2e tests, integration tests, and
  load tests.
- Documentation of required local services and browser/container prerequisites.

Out of scope:

- Replacing existing tests wholesale.
- Requiring load tests on every local edit.
- Hosted CI provider configuration unless a later implementation task chooses a
  specific provider.

## Test Tiers

- Default pytest suite: fast unit, route, service, model, validation, and
  protocol tests; excludes browser e2e, container integration, and load tests.
- Browser UI suite: Playwright-backed tests for public and authenticated
  NiceGUI flows.
- Property suite: Hypothesis-backed tests for broad generated input spaces and
  security-sensitive invariants.
- API security suite: Tavern-backed YAML tests for REST endpoint contracts,
  negative cases, route boundaries, and secret-free error responses.
- Container integration suite: Testcontainers-backed tests for PostgreSQL and
  production-like service dependencies.
- Load suite: Locust scenarios for auth, token issuance, metadata, UserInfo,
  and selected UI-adjacent paths.

## Task Commands

The implementation must expose explicit `taskipy` commands for each test type:

- `poetry run task test`: default fast pytest suite.
- `poetry run task test_unit`: unit-focused pytest suite.
- `poetry run task test_property`: Hypothesis property-based suite.
- `poetry run task test_api_security`: Tavern API security suite.
- `poetry run task test_integration`: Testcontainers-backed integration suite.
- `poetry run task test_e2e`: Playwright browser UI suite.
- `poetry run task test_load`: headless Locust load smoke test.
- `poetry run task test_all`: complete non-load verification suite.

Optional helper commands:

- `poetry run task playwright_install`: install Chromium for Playwright.
- `poetry run task test_load_ui`: open Locust's web UI for exploratory load
  runs.

## Rules

- The default `poetry run task test` command remains safe for frequent local
  execution and must not require Docker, browsers, or external network access.
- Browser e2e tests must remain marked with `e2e`.
- Container-backed tests must use a dedicated marker, such as `integration` or
  `container`.
- Load tests must not run as part of unit, integration, or e2e suites.
- Tests must not rely on committed local databases, `.env` secrets, or
  developer-specific browser state.
- Tests that manipulate time-sensitive tokens must use deterministic time
  control, such as `freezegun`, where practical.

## Acceptance Criteria

- Given a developer runs `poetry run task test`, then only the default fast test
  suite runs.
- Given a developer runs a test task command, then the command name identifies
  the test tier it runs.
- Given a developer runs the browser e2e task, then Playwright tests run against
  an isolated live SatOIDC server.
- Given a developer runs the property test task, then Hypothesis tests exercise
  bounded generated inputs for documented invariants.
- Given a developer runs the API security task, then Tavern verifies endpoint
  security contracts and negative cases.
- Given a developer runs the container integration task, then PostgreSQL-backed
  tests run through Testcontainers.
- Given a developer runs the load task, then Locust executes documented
  scenarios against a selected base URL.
- Given a new feature affects auth, OIDC, LNURL, persistence, or UI, then at
  least one relevant automated test tier is updated.

## Implementation Progress

- Pytest markers and taskipy commands exist for unit, property, API security,
  integration, e2e, load, and non-load suites.
- The first bounded property tests cover redirect safety and validators.
- API security smoke coverage exercises public metadata and route-boundary
  contracts through Python and Tavern tests.
- The first Locust smoke scenario covers public metadata and auth pages against
  a configured base URL.

## Traceability

- Pytest and extensions: `pytest-extensions.md`
- Hypothesis property tests: `hypothesis-property.md`
- Tavern API security tests: `tavern-api-security.md`
- Browser UI: `playwright-ui.md`
- Load testing: `locust-load.md`
- Container integration: `testcontainers-integration.md`
