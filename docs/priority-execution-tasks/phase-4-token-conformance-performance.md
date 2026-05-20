# Phase 4: Token Lifecycle, Conformance, And Performance

Status: open
Priority: P1/P3
Recommended agents: OIDC QA, performance engineering

## Task 4.1: Expand Token Lifecycle E2E Coverage

1. Clear task name: Expand refresh, revocation, introspection, and UserInfo e2e.
2. Technical objective: prove token lifecycle behavior in a real browser/client
   flow.
3. Detailed scope: authorization code flow, refresh rotation, old refresh token
   rejection, revocation, introspection ownership, UserInfo scope behavior.
4. Required inputs: `specs/flows/token-lifecycle.md`,
   `specs/flows/authorization-code.md`,
   `satoidc/tests/e2e/test_oauth_authorization_code_e2e.py`.
5. Expected outputs: e2e tests for token lifecycle.
6. Dependencies: existing e2e server fixture.
7. Completion criteria: revoked and rotated tokens fail as expected and valid
   tokens still work.
8. Validation/test criteria: `cd satoidc; poetry run task test_e2e`.
9. Recommended specialized agent: OIDC QA agent.
10. Priority: P1.
11. Estimated complexity: M.
12. Technical risks: flaky timing around token expiration or browser redirects.
13. Potentially affected files/components: `tests/e2e/`, test fixtures.
14. Contracts/interfaces involved: OIDC Contract, OAuth Token Lifecycle Flow.
15. Integration notes: complete before conformance evidence if possible.

### Subtasks

- [x] Reuse existing OAuth browser fixture.
- [x] Exchange authorization code for tokens.
- [x] Refresh and verify rotation.
- [x] Revoke token and verify failure.
- [x] Introspect with correct and incorrect client.
- [x] Assert UserInfo claims by scope.

## Task 4.2: Decide LNURL `action=auth` Contract

1. Clear task name: Document or remove LNURL `action=auth`.
2. Technical objective: eliminate uncontracted LNURL behavior before production.
3. Detailed scope: inspect usage, decide whether `auth` is experimental,
   removed, or formalized; update code/spec/tests accordingly.
4. Required inputs: `satoidc/satoidc/routes/lnurl_auth.py`,
   `satoidc/satoidc/auth/lnurl.py`, `specs/flows/lnurl-auth.md`,
   `satoidc/tests/test_lnurl_auth.py`.
5. Expected outputs: documented decision and matching implementation/tests.
6. Dependencies: none.
7. Completion criteria: no LNURL action remains with undefined production
   semantics.
8. Validation/test criteria: LNURL unit/route tests pass.
9. Recommended specialized agent: LNURL/auth architect.
10. Priority: P1.
11. Estimated complexity: M.
12. Technical risks: breaking hidden consumers if `auth` is removed.
13. Potentially affected files/components: LNURL route/auth modules, tests,
    specs.
14. Contracts/interfaces involved: LNURL-auth Flow.
15. Integration notes: if kept, document the exact callback contract.

### Subtasks

- [x] Search code/tests/docs for `action=auth`.
- [x] Decide keep/remove/formalize.
- [x] Update specs.
- [x] Update implementation and tests.

## Task 4.3: Prepare OIDC Basic OP Conformance Environment

1. Clear task name: Prepare disposable OIDC Basic OP conformance environment.
2. Technical objective: make OpenID Foundation conformance testing
   reproducible without real operator data.
3. Detailed scope: test instance, issuer configuration, seeded user/client,
   disposable secrets, documented setup steps.
4. Required inputs: `specs/features/oidc-conformance/spec.md`, Compose,
   runtime config docs, OIDC contract.
5. Expected outputs: `docs/conformance.md` with setup section or a dedicated
   conformance runbook.
6. Dependencies: Task 4.1 recommended.
7. Completion criteria: conformance target instance can be started from clean
   state and exposes expected discovery/JWKS/token behavior.
8. Validation/test criteria: smoke verify discovery, JWKS, authorization, token,
   and UserInfo.
9. Recommended specialized agent: OIDC QA/conformance agent.
10. Priority: P2.
11. Estimated complexity: M.
12. Technical risks: unstable issuer URL or accidental use of production
    secrets.
13. Potentially affected files/components: docs, optional scripts/examples.
14. Contracts/interfaces involved: OIDC Contract.
15. Integration notes: do not claim conformance until Task 4.4 records results.

### Subtasks

- [x] Select Basic OP profile.
- [x] Define seed data.
- [x] Document environment variables.
- [x] Add smoke checklist.

## Task 4.4: Run And Record OIDC Basic OP Evidence

1. Clear task name: Run and document OIDC Basic OP evidence.
2. Technical objective: record real conformance evidence and known deviations.
3. Detailed scope: run OpenID Foundation OP tests against disposable SatOIDC,
   capture pass/fail status, document deviations, create follow-up specs for
   protocol bugs.
4. Required inputs: Task 4.3 environment, `specs/features/oidc-conformance/spec.md`.
5. Expected outputs: completed `docs/conformance.md` and linked issues/specs for
   failures.
6. Dependencies: Task 4.3.
7. Completion criteria: result is documented with date, tested profile, config,
   and known limitations.
8. Validation/test criteria: conformance report or reproducible summary exists.
9. Recommended specialized agent: OIDC conformance QA agent.
10. Priority: P3.
11. Estimated complexity: L.
12. Technical risks: conformance failures may require protocol changes.
13. Potentially affected files/components: `docs/conformance.md`,
    `docs/known-issues.md`, specs.
14. Contracts/interfaces involved: OIDC Contract.
15. Integration notes: update README only with accurate, evidence-backed claims.

### Subtasks

- Run suite.
- Triage failures.
- Record results.
- Open follow-up specs for product bugs.

## Task 4.5: Publish Load Baseline For `/oauth/token`

1. Clear task name: Publish token endpoint load baseline.
2. Technical objective: establish conservative capacity guidance for small
   self-hosted deployments.
3. Detailed scope: Locust scenario for metadata/JWKS plus token issuance with
   explicit seed data, PostgreSQL target, p95 latency, failure rate, CPU/RAM/DB
   assumptions.
4. Required inputs: `specs/features/quality-testing/locust-load.md`,
   `satoidc/tests/load/locustfile.py`, deployment docs.
5. Expected outputs: improved Locust scenario and documented baseline.
6. Dependencies: PostgreSQL test environment.
7. Completion criteria: report includes request count, failure rate, p95
   latency, environment, and target config.
8. Validation/test criteria: `cd satoidc; poetry run task test_load` against a
   healthy local server.
9. Recommended specialized agent: performance engineer.
10. Priority: P2.
11. Estimated complexity: M.
12. Technical risks: publishing SQLite or laptop-only results as production
    guidance.
13. Potentially affected files/components: `tests/load/locustfile.py`, docs.
14. Contracts/interfaces involved: OAuth token endpoint, Token Lifecycle Flow.
15. Integration notes: keep load tests outside default local and CI suites.

### Subtasks

- Add explicit seed requirements.
- Add token issuance scenario if missing.
- Run against PostgreSQL.
- Document conservative baseline.

