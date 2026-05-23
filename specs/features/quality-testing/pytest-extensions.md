# Spec: Pytest And Test Extensions

## Status

- Status: draft
- Owner: project maintainers
- Created: 2026-05-16
- Updated: 2026-05-23
- Related code:
  - `satoidc/pyproject.toml`
  - `satoidc/tests/conftest.py`
  - `satoidc/tests/`
- Related specs:
  - `specs/features/quality-testing/spec.md`

## Intent

Standardize the default pytest suite and the pytest extensions used by SatOIDC
so tests stay fast, deterministic, and explicit about which risks they cover.

## Context

The project already configures pytest with NiceGUI's testing plugin, coverage,
asyncio support, and an `e2e` marker. Development dependencies include
`pytest`, `pytest-cov`, `pytest-asyncio`, `pytest-playwright-asyncio`,
`freezegun`, `factory-boy`, and `testcontainers`. Hypothesis is specified
separately for property-based tests, and Tavern is specified separately for
declarative API security tests.

## Scope

In scope:

- Default pytest command behavior.
- Test markers.
- Async database/session fixtures.
- Coverage expectations.
- Factories and deterministic time helpers.

Out of scope:

- Browser automation details, covered by `playwright-ui.md`.
- PostgreSQL container details, covered by `testcontainers-integration.md`.
- Load tests, covered by `locust-load.md`.

## Rules

- `poetry run task test` runs the default fast pytest suite and remains the
  primary local validation command.
- `poetry run task test_unit` runs unit-focused tests and excludes browser,
  container, load, and slow markers.
- `poetry run task test_all` runs the complete non-load verification suite when
  local browser and container prerequisites are available.
- Default tests must use isolated databases and must not read or write
  `satoidc/database.db` or `satoidc/satoidc.db`.
- Tests for async routes and SQLAlchemy behavior use async fixtures instead of
  mixing blocking database access into event-loop code.
- Token, challenge, expiry, and rotation tests use deterministic time control
  for expiration boundaries.
- Factories may be introduced for repeated user, permission, client, token, and
  LNURL challenge setup.
- Coverage excludes must stay narrow and justified, especially for visual-only
  NiceGUI rendering helpers.
- The default measured suite must keep 100% line coverage through
  `coverage report --fail-under=100`.
- AI-assisted production code must include tests in the same change, preferably
  written first as the red step of a TDD loop.
- New markers must be documented in `pyproject.toml`.

## Recommended Markers

- `e2e`: browser end-to-end tests.
- `integration`: tests that require Docker, Testcontainers, or production-like
  external services.
- `property`: Hypothesis/property-based tests with bounded runtime.
- `property_slow`: heavier property tests that are excluded from the property
  smoke command unless explicitly selected.
- `api_security`: Tavern-backed HTTP security regression tests.
- `api_contract`: broader Tavern API contract tests, if separated from security
  cases.
- `load`: load/performance smoke tests, if pytest is used to orchestrate them.
- `slow`: tests that are valid locally but too expensive for the default suite.

## Task Commands

- `poetry run task test`: `pytest -m "not e2e and not integration and not container and not property and not load and not slow"`
- `poetry run task test_unit`: `pytest -m "not e2e and not integration and not container and not property and not load and not slow"`
- `poetry run task test_property`: `pytest -m "property and not property_slow" --no-cov`
- `poetry run task test_api_security`: `pytest -m api_security tests/api --no-cov`
- `poetry run task test_integration`: `pytest -m "(integration or container) and not load" --no-cov`
- `poetry run task test_all`: `pytest -m "not load and not slow"`
- `poetry run task coverage_html`: `coverage html`
- `post_test`: `coverage html`

## Acceptance Criteria

- Given the default test command runs, then e2e, integration, load, and slow
  tests are excluded unless explicitly selected.
- Given `test_unit` runs, then it does not require Docker, Playwright browsers,
  Locust, or external services.
- Given a test covers an expiration window, then it does not depend on wall
  clock timing.
- Given a test creates users, clients, permissions, tokens, or challenges, then
  setup is isolated and repeatable.
- Given coverage is generated, then source modules are measured without relying
  on generated local databases or browser state.
- Given the default suite completes, then measured line coverage is 100% and a
  drop below 100% fails the command.

## Implementation Notes

- Keep `satoidc/tests/conftest.py` as the shared fixture boundary for default
  tests.
- Add feature-specific fixtures near the tests that need them unless they are
  reused broadly.
- Prefer `factory-boy` only where it removes repeated setup noise.
- Keep coverage HTML generation automatic after `task test` so the local
  `htmlcov` report reflects the latest default-suite run. `coverage_html`
  remains available for explicit regeneration.
- Keep coverage-driven refactors small. Extract testable helpers or services
  when route/UI glue makes behavior hard to exercise directly.
