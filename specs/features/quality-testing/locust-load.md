# Spec: Locust Load Tests

## Status

- Status: draft
- Owner: project maintainers
- Created: 2026-05-16
- Updated: 2026-05-17
- Related code:
  - `satoidc/pyproject.toml`
  - `satoidc/tests/load/`
  - `satoidc/locustfile.py`
- Related specs:
  - `specs/features/quality-testing/spec.md`
  - `specs/flows/token-lifecycle.md`
  - `specs/flows/authorization-code.md`
  - `specs/flows/deployment.md`

## Intent

Add repeatable Locust load tests that establish baseline performance and
failure behavior for the most important SatOIDC authentication and OAuth/OIDC
paths.

## Context

The backlog already calls for lightweight load/concurrency checks around token
issuance. The current development dependencies do not include Locust, and the
default pytest suite verifies correctness rather than concurrency behavior.

## Scope

In scope:

- Locust dependency and task command.
- Local headless load runs against a configured base URL.
- Load scenarios for metadata, login-related public pages, token issuance,
  UserInfo, and selected authenticated or seeded flows.
- Baseline thresholds for errors and latency in local development.
- Documentation of setup requirements for SQLite and PostgreSQL runs.

Out of scope:

- Internet-scale benchmark claims.
- Requiring load tests in every default local test run.
- Testing third-party wallets or external relying-party infrastructure under
  load.

## Rules

- Load tests must run only when explicitly requested.
- Load tests must accept a target base URL instead of starting an uncontrolled
  server implicitly.
- Production-like load tests should use PostgreSQL rather than SQLite.
- Test users, clients, and tokens must be seeded by documented setup helpers or
  fixtures.
- Locust scenarios must avoid logging secrets, passwords, access tokens,
  refresh tokens, authorization codes, or private keys.
- Reported results must include request count, failure rate, p95 latency, and
  target configuration.

## Task Commands

- `poetry run task test_load`: `locust -f tests/load/locustfile.py --headless --users 5 --spawn-rate 1 --run-time 1m --host http://127.0.0.1:8000`
- `poetry run task test_load_ui`: `locust -f tests/load/locustfile.py --host http://127.0.0.1:8000`

The implementation may allow overriding users, spawn rate, run time, and host
through environment variables or extra task arguments, but the default command
must remain a bounded local smoke test.

## Core Scenarios

- Discovery and JWKS reads.
- Login and registration page GET requests.
- Token endpoint issuance for seeded clients.
- UserInfo requests with valid bearer tokens.
- OAuth client metadata or dashboard-adjacent endpoints where safe and useful.

## Acceptance Criteria

- Given Locust is installed, when the load task runs against a healthy local
  server, then a bounded smoke test completes and records summary metrics.
- Given `poetry run task test_load` runs, then it executes Locust in headless
  mode with bounded local smoke-test defaults.
- Given the target server returns errors, then the Locust run fails clearly.
- Given token issuance is tested, then seeded client/user data is explicit and
  reproducible.
- Given load results are published in docs or CI output, then secrets and token
  values are redacted.

## Implementation Notes

- Prefer `satoidc/tests/load/locustfile.py` or `satoidc/locustfile.py`, but keep
  the chosen path documented in `pyproject.toml`.
- Start with short smoke settings, then add heavier profiles only after the
  basic scenario is stable.
