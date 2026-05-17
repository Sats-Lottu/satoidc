# Backlog Priority Plan

Updated: 2026-05-17

Status: historical. The active priority backlog was completed on 2026-05-17;
keep this file as the execution-plan record and use
`docs/priority-execution-backlog.md` for any new open queue.

This plan orders the active execution backlog into implementation branches,
groups related work, and defines an initial commit sequence. It does not
authorize implementation by itself.

Planned branch:

- `docs/backlog-priority-plan`

## Priority Rationale

Prioritization uses four signals:

- Security exposure and production-hardening impact.
- Dependency ordering between specs.
- Ability to write focused tests before production code.
- Size and reversibility of each implementation commit.

## Recommended Implementation Order

### 1. Harden Public Route Boundary

Backlog item: 2.

Spec:

- `specs/features/public-route-boundary/spec.md`

Reason:

- This is high-priority security work with a narrow implementation surface.
- It reduces accidental exposure risk before more routes are added for account
  recovery, setup, and operations.
- The spec is concrete enough to implement test-first.

Test-first plan:

- Add unit tests for exact and segment-boundary public path classification.
- Add middleware regression tests for `/oauth-settings`, `/api-admin`, and
  `/.well-knownness`.
- Verify legitimate public paths such as `/oauth/token`,
  `/.well-known/openid-configuration`, and intended `/api/...` paths still pass.

Proposed commits:

1. `test(auth): Cover public route boundaries`
2. `fix(auth): Harden public path matching`
3. `docs(security): Document public route rules`

### 2. Validate Runtime And Database Startup Assumptions

Backlog items: 1 and 4.

Specs:

- `specs/features/application-setup/spec.md`
- `specs/contracts/database.md`
- `specs/contracts/runtime-config.md`
- `specs/flows/deployment.md`

Reason:

- Setup bootstrap and database URL validation are coupled at startup.
- The database support matrix should be explicit before adding heavier
  production features and migration-dependent account recovery.
- This should come before external signing so production failure modes are
  predictable.

Test-first plan:

- Add unit tests for generated/operator-managed/optional runtime value
  classification.
- Add tests for async/sync database URL consistency.
- Add integration coverage for setup idempotence with existing valid secrets
  and existing root permission.
- Add production fail-closed tests for placeholder secrets and missing issuer.

Proposed commits:

1. `test(config): Cover startup validation rules`
2. `feat(setup): Classify bootstrap settings`
3. `fix(config): Validate database URL pairs`
4. `docs(deploy): Define database support matrix`

### 3. Add Operational Observability Baseline

Backlog item: 6.

Spec:

- `specs/features/operational-observability/spec.md`

Reason:

- Logging should exist before Transit signing and email recovery introduce more
  security-sensitive failure paths.
- The first pass can use standard-library logging and caplog tests without
  introducing a telemetry dependency.

Test-first plan:

- Add `caplog` tests for selected middleware/auth failure paths.
- Add assertions that passwords, tokens, private JWKs, client secrets, and raw
  recovery values are absent from logs.
- Keep logs structured by event name, component, outcome, and sanitized reason.

Proposed commits:

1. `test(logging): Assert sanitized auth logs`
2. `feat(logging): Add auth event logging`
3. `feat(logging): Add mutation failure logs`

### 4. Add OpenBao-Compatible External Signing Backend

Backlog item: 3.

Spec:

- `specs/features/external-signing-backend/spec.md`

Reason:

- This remains a high-priority production hardening item, but it depends on
  clean runtime validation and useful operational failure logs.
- The first implementation should introduce a narrow signing backend boundary
  before a full Transit adapter.

Test-first plan:

- Add unit tests for signing backend selection.
- Add adapter-stub integration tests for signing and failure behavior.
- Add regression tests proving private key material is absent from logs,
  responses, and audit events.
- Keep database signing behavior unchanged when
  `OIDC_SIGNING_BACKEND=database`.

Proposed commits:

1. `test(oidc): Cover signing backend selection`
2. `refactor(oidc): Add signing backend boundary`
3. `feat(oidc): Add transit signing adapter`
4. `docs(oidc): Document internal signing risk`

### 5. Implement Email Verification And Account Recovery

Backlog item: 10.

Spec:

- `specs/features/email-verification/spec.md`

Reason:

- This is high user value but touches persistence, public routes, profile UI,
  email delivery, UserInfo, and security-sensitive token handling.
- It should start after public route hardening and logging exist.

Test-first plan:

- Add migration/default/index tests or database contract checks for
  `email_verified`, `email_verified_at`, and `email_tokens`.
- Add unit tests for token generation, hashing, lookup, expiry, wrong-purpose,
  wrong-email, and single-use consumption.
- Add route tests for registration verification creation, profile email change,
  resend verification, recovery enumeration resistance, and reset completion.
- Add UserInfo test for `email_verified` with the `email` scope.

Proposed commits:

1. `test(email): Cover verification tokens`
2. `feat(email): Add verification persistence`
3. `feat(email): Send verification messages`
4. `test(recovery): Cover password reset flow`
5. `feat(recovery): Add password reset routes`
6. `feat(oidc): Expose email_verified claim`

### 6. Extract Persistence-Heavy UI Actions Into Services

Backlog item: 5.

Spec:

- `specs/features/route-service-extraction/spec.md`

Reason:

- Service extraction is important, but it is safer after account recovery and
  client/security behavior settle.
- It should be incremental and behavior-preserving.

Test-first plan:

- Pick one vertical slice first, likely profile email/password actions.
- Add unit tests for the new service helper before moving route logic.
- Re-run existing authenticated UI and OAuth browser tests after each slice.

Proposed commits:

1. `test(profile): Cover profile services`
2. `refactor(profile): Extract account services`
3. `test(clients): Cover client services`
4. `refactor(clients): Extract dashboard services`

### 7. Refactor Test Layer For Quality Specs

Backlog item: 11.

Specs:

- `specs/features/quality-testing/spec.md`
- `specs/features/quality-testing/pytest-extensions.md`
- `specs/features/quality-testing/hypothesis-property.md`
- `specs/features/quality-testing/tavern-api-security.md`
- `specs/features/quality-testing/playwright-ui.md`
- `specs/features/quality-testing/locust-load.md`
- `specs/features/quality-testing/testcontainers-integration.md`

Reason:

- The quality test commands are useful across the whole project, but adding
  every test layer at once is large.
- Introduce markers and task commands first, then add property/API/container
  suites as focused follow-up work.

Test-first plan:

- Add command/marker smoke tests where practical.
- Ensure `poetry run task test` remains fast and excludes e2e/container/load.
- Add one representative test per new tier before expanding coverage.

Proposed commits:

1. `test(pytest): Add quality markers`
2. `build(test): Add test task commands`
3. `test(property): Add invariant tests`
4. `test(api): Add security contract smoke`
5. `test(integration): Add postgres smoke`

### 8. Add Token Issuance Load/Concurrency Checks

Backlog item: 7.

Specs:

- `specs/contracts/authlib-adapter.md`
- `specs/flows/token-lifecycle.md`
- `specs/features/quality-testing/locust-load.md`

Reason:

- This depends on the quality-testing task structure and ideally PostgreSQL
  integration support.
- It should stay separate from the default test suite.

Test-first plan:

- Add a minimal headless Locust smoke scenario for `/oauth/token`.
- Ensure it can target a configured base URL and does not run by default.
- Document expected local prerequisites and non-goal of strict performance
  thresholds in the first pass.

Proposed commits:

1. `test(load): Add token issuance smoke`
2. `docs(test): Document load test usage`

### 9. Remove LNURL Schema Compatibility Shim

Status: completed.

Backlog item: 8.

Reference:

- `docs/changes-2026-05-08.md`

Reason:

- This is low risk and can be done when no imports depend on the shim.
- It should not be mixed into security or recovery branches.

Test-first plan:

- Add or update import regression checks if any compatibility expectation
  remains.
- Use `rg` to confirm there are no imports from
  `satoidc.satoidc.auth.lnurl_schemas`.

Proposed commits:

1. `test(lnurl): Confirm schema import paths`
2. `refactor(lnurl): Remove schema shim`

### 10. Normalize Or Archive relatorio.md

Status: completed.

Backlog item: 9.

Reason:

- This is documentation hygiene and should not block production hardening.

Test-first plan:

- No automated test required unless links are added to an indexed doc.
- Manually verify encoding after the edit.

Proposed commits:

1. `docs(report): Archive legacy report`

## Suggested Branch Breakdown

- `bugfix/public-route-boundary`
- `feature/setup-bootstrap-validation`
- `feature/operational-observability`
- `feature/oidc-transit-signing`
- `feature/email-account-recovery`
- `refactor/route-service-extraction`
- `test/quality-testing-baseline`
- `test/token-load-smoke`
- `refactor/remove-lnurl-schema-shim`
- `docs/archive-legacy-report`

## Questions For Approval

Mark one option or write a custom answer before implementation starts.

### Q1. OpenBao Local Support Shape

- [ ] A. External endpoint only for the first implementation.
- [x] B. Add a Docker Compose profile for local OpenBao.
- [ ] C. Document operator setup only; no local automation yet.

Open answer:

```text
use https://testcontainers.com/?language=python para testes de integração
```

### Q2. Password Reset Session Policy

- [ ] A. Keep existing browser sessions valid for the first MVP.
- [x] B. Revoke all active sessions after password reset.
- [ ] C. Add session revocation only after a separate session-store spec.

Open answer:

```text

```

### Q3. Email Delivery Backend

- [x] A. Start with console plus SMTP behind a narrow interface.
- [ ] B. Start with SMTP only.
- [ ] C. Define a pluggable provider interface before implementation.

Open answer:

```text
Comece com uma interface de entrega de e-mail simplificada e forneça duas implementações iniciais: um backend de console para desenvolvimento/teste local e um backend SMTP para entrega real. Isso mantém a primeira versão simples, evita abstrações prematuras e impede que o aplicativo dependa diretamente dos detalhes do SMTP.

O backend selecionado pode ser configurado por meio de variáveis ​​de ambiente, por exemplo, EMAIL_BACKEND=console ou EMAIL_BACKEND=smtp.

Um sistema de provedores totalmente plugável pode ser introduzido posteriormente, se necessário, por exemplo, para Resend, SES, Mailgun, Brevo ou Postmark.
```

### Q4. UserInfo Email Claim Policy

- [ ] A. Emit `email` and `email_verified=false` for unverified email.
- [x] B. Emit `email` only after verification.
- [ ] C. Keep current `email` behavior and add `email_verified` later.

Open answer:

```text

```

### Q5. First Implementation Branch

- [x] A. Start with `bugfix/public-route-boundary`.
- [ ] B. Start with `feature/setup-bootstrap-validation`.
- [ ] C. Start with `feature/email-account-recovery`.

Open answer:

```text

```

## Implementation Authorization

- [x] I authorize implementation to start from the selected first branch.
- [x] I authorize tests to be written first, followed by implementation.
- [x] I authorize updating specs if implementation reveals an ambiguity.
- [x] I want another planning revision before implementation starts.

Authorization notes:

```text

```
