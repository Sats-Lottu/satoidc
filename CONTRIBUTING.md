# Contributing

Thank you for improving SatOIDC. This project handles identity, OAuth2/OIDC,
LNURL Auth, secrets, and deployment behavior, so contributions must be small,
reviewable, testable, and explicit about risk.

## Language

All repository content must be written in English. This includes code, comments,
docstrings, log messages, specs, docs, tests, examples, Git metadata, and pull
request text.

Conversations with AI assistants may happen in any language preferred by the
user, but files, commits, and pull requests committed to the repository must be
in English.

## Development Workflow

1. Read `README.md`, `docs/README.md`, `specs/index.md`, and `AGENTS.md`.
2. Create or update a spec before changing behavior that affects auth,
   OAuth2/OIDC, LNURL Auth, persistence, security, public contracts, or UI
   flows.
3. Start behavior changes with a failing test, then implement the smallest code
   change that makes it pass.
4. Keep changes narrow and reversible.
5. Add focused tests for behavior changes.
6. Run relevant checks before submitting.
7. Explain validation results and residual risks in the pull request.

## Test-Driven Development

SatOIDC uses Test-Driven Development for new behavior and bug fixes. The
default measured test suite must stay at 100% line coverage. `poetry run task
test` is configured to fail below that threshold and to refresh the HTML
coverage report through `post_test`.

Do not merge production code that lacks tests for its intended behavior. If a
path is difficult to test, refactor it into a focused service, helper, or
adapter boundary before adding more behavior.

## Commit Style

Use Conventional Commits in English:

```text
fix(lnurl): Reject consumed challenges
docs(setup): Clarify bootstrap states
test(oauth): Cover refresh token reuse
```

Do not commit secrets, `.env` files, local databases, virtual environments,
coverage output, build artifacts, or NiceGUI local storage.

## AI-Assisted Contributions

AI tools may be used as engineering assistants, but a human contributor remains
responsible for the entire contribution.

Requirements:

- Review and understand all AI-assisted changes before submission.
- Include tests in the same change for production code generated or
  substantially edited with AI assistance.
- Keep the default measured suite at 100% line coverage; do not lower coverage
  thresholds to accommodate generated code.
- Disclose meaningful AI assistance with an `Assisted-by:` trailer or pull
  request metadata.
- Do not list AI tools as authors, signers, reviewers, approvers, or legal
  certifiers.
- Do not use AI to bypass required tests, security review, licensing review, or
  human approval.
- Include a prompt summary or tool summary when a substantial portion of the
  contribution was generated.
- Expect additional review for large generated patches, security-sensitive
  changes, dependency changes, and architecture changes.

Suggested trailer:

```text
Assisted-by: Codex:GPT-5.5
```

If DCO-style sign-off is ever required, only the human contributor may add a
`Signed-off-by:` trailer. AI tools must never add or be listed in
`Signed-off-by:` trailers.

## Human Accountability

Before submitting an AI-assisted change, the human contributor must verify:

- they understand the code, docs, tests, and configuration being submitted;
- the change fits the existing architecture and project specs;
- copied or generated material is license-compatible;
- no proprietary or unclear-origin code was introduced;
- security and operational risks were considered;
- tests and static checks are appropriate for the risk level;
- rollback or recovery behavior is clear for high-impact changes.

Maintainers may ask contributors to split large patches, add tests, explain
generated sections, provide prompts or summaries, or withdraw changes that the
submitter cannot explain and defend.

## Security-Sensitive Changes

Use extra scrutiny for changes touching:

- authentication and authorization;
- OAuth2/OIDC, JWT, PKCE, consent, and client registration;
- LNURL Auth and Lightning wallet flows;
- secrets, signing keys, cryptography, sessions, and cookies;
- database access, migrations, and query scope;
- Docker, deployment, CI/CD, and supply chain behavior;
- CSRF, XSS, SSRF, SQL injection, path traversal, uploads, and serialization.

Security-sensitive pull requests should include tests, threat/risk notes, and
manual validation when automated checks cannot cover the behavior.

## Validation

Common commands:

```powershell
cd satoidc
poetry run ruff check
poetry run task test
poetry run task test_e2e
```

Run the smallest relevant set for the change. If a check is skipped, explain why
in the pull request.
