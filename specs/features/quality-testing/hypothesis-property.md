# Spec: Hypothesis Property Tests

## Status

- Status: draft
- Owner: project maintainers
- Created: 2026-05-16
- Updated: 2026-05-17
- Related code:
  - `satoidc/pyproject.toml`
  - `satoidc/tests/`
  - `satoidc/satoidc/validators.py`
  - `satoidc/satoidc/auth/security.py`
  - `satoidc/satoidc/auth/lnurl.py`
  - `satoidc/satoidc/auth/oauth2.py`
- Related specs:
  - `specs/features/quality-testing/spec.md`
  - `specs/features/quality-testing/pytest-extensions.md`
  - `specs/contracts/security-session.md`
  - `specs/flows/lnurl-auth.md`
  - `specs/flows/token-lifecycle.md`

## Intent

Use Hypothesis property-based tests to exercise input spaces that are too broad
for example-based tests, especially validation, redirect safety, token
lifecycle, scope handling, and malformed LNURL/OIDC inputs.

## Context

SatOIDC contains security-sensitive parsing and validation rules. Many of these
rules have clear invariants, such as "unsafe redirects never pass",
"malformed LNURL callback inputs fail closed", and "claims are only emitted for
granted scopes". Hypothesis can generate edge cases and shrink failures to small
counterexamples.

## Scope

In scope:

- Adding Hypothesis as a development dependency.
- Adding a dedicated pytest marker for property-based tests.
- Property tests for pure or mostly pure helpers.
- Property tests for route/service behavior only when the generated input space
  is bounded and deterministic.

Out of scope:

- Browser UI fuzzing.
- Load testing.
- Replacing existing example-based tests.
- Unbounded random tests that make local runs flaky or slow.

## Candidate Properties

- Redirect safety:
  - Accepted redirects are relative paths beginning with one `/`.
  - External, host-relative, empty, bare-relative, control-character, and
    whitespace-padded redirects fail closed.
- Validators:
  - Login, nickname, password, and email validators never raise unexpected
    exceptions for arbitrary strings.
  - Invalid values return structured validation failures without database work.
- LNURL callback parsing:
  - Malformed `k1`, `key`, and `sig` inputs fail without authenticating or
    linking a wallet.
- Token lifecycle:
  - Expired, consumed, wrong-purpose, malformed, or wrong-user tokens never
    mutate account state.
- OIDC scopes and claims:
  - UserInfo and ID Token helpers never emit claims outside granted scopes.
- Runtime configuration:
  - Invalid production secret and database URL combinations fail fast.

## Rules

- Property tests must be marked `property`.
- Property tests must be deterministic enough for local and CI use.
- Tests that use generated strings must bound size and character categories when
  the full Unicode space adds noise without useful coverage.
- Hypothesis examples that reveal regressions should be kept automatically in
  the Hypothesis database when available, but the test must remain reproducible
  without relying on local database state.
- Tests must not log secrets, generated tokens, authorization codes, passwords,
  or private keys.
- Slow or stateful properties must use a separate marker, such as
  `property_slow`, and stay out of the default property smoke command.

## Task Commands

- `poetry run task test_property`: `pytest -m property`

Optional heavier command:

- `poetry run task test_property_slow`: `pytest -m "property or property_slow"`

## Acceptance Criteria

- Given `poetry run task test_property` runs, then only Hypothesis/property
  tests are selected.
- Given arbitrary redirect inputs, when checked by property tests, then unsafe
  values fail closed and accepted values satisfy the redirect contract.
- Given arbitrary validator inputs, when validation runs, then the validators
  return booleans or structured errors without unexpected exceptions.
- Given malformed LNURL or token inputs, when property tests exercise them, then
  no authentication, wallet linking, token issuance, or password mutation occurs
  unless the generated value satisfies the full valid contract.
- Given a property test finds a failure, then Hypothesis shrinks it to a
  readable counterexample suitable for a focused regression test.

## Implementation Notes

- Add `hypothesis` to the development dependency group.
- Add `property` and `property_slow` markers to `pyproject.toml`.
- Prefer `satoidc/tests/test_*_properties.py` files for discoverability.
- Start with pure helpers such as redirect validation and field validators
  before moving into database-backed stateful properties.
