# AGENTS.md

## Project Overview

- SatOIDC is a Python OpenID Connect provider that combines OAuth2/OIDC flows with Bitcoin/Lightning LNURL-auth.
- The runnable app lives in `satoidc/`; the FastAPI/NiceGUI application package is `satoidc/satoidc/`.
- OAuth/OIDC protocol integration is under `satoidc/satoidc/auth/`, `satoidc/satoidc/fastapi_oauth2/`, and `satoidc/satoidc/routes/oauth2.py`.
- Browser-facing NiceGUI routes live in `satoidc/satoidc/routes/`; examples live in `examples/`.
- Start project orientation from `README.md`, `docs/README.md`, `specs/index.md`, and `agent-memory/index.md` before doing broad analysis again.

## Documentation Map

- `README.md`: human-facing overview, endpoints, commands, roadmap, and links to deeper docs.
- `docs/README.md`: index for architecture, project analysis, and known issues.
- `docs/architecture.md`: current system map and request flows.
- `docs/project-analysis.md`: broad repository analysis and implementation notes.
- `docs/known-issues.md`: prioritized risks and technical debt.
- `docs/priority-execution-backlog.md`: temporary active task queue; keep only open work here.
- `docs/priority-execution-history.md`: summary of completed backlog items removed from the active queue.
- `DESIGN.md`: source of truth for NiceGUI interface conventions.
- `specs/index.md`: active and historical Spec-Driven Development entries.
- `agent-memory/index.md`: durable agent memory with decisions, commands, state, risks, and open questions.

## Build And Test Commands

- Install dependencies: `cd satoidc; poetry install`
- Apply migrations: `cd satoidc; poetry run alembic upgrade head`
- Run development server: `cd satoidc; poetry run task run`
- Run tests: `cd satoidc; poetry run task test`
- Install browser for e2e tests: `cd satoidc; poetry run task playwright_install`
- Run browser e2e tests: `cd satoidc; poetry run task test_e2e`
- Run lint: `cd satoidc; poetry run ruff check`
- Run public client example: `cd satoidc; poetry run task start_public_client <client-id>`

Planned quality-testing commands are specified but not implemented yet:

- Unit-focused tests: `cd satoidc; poetry run task test_unit`
- Hypothesis property tests: `cd satoidc; poetry run task test_property`
- Tavern API security tests: `cd satoidc; poetry run task test_api_security`
- Testcontainers integration tests: `cd satoidc; poetry run task test_integration`
- Locust load smoke tests: `cd satoidc; poetry run task test_load`
- Complete non-load suite: `cd satoidc; poetry run task test_all`

## Git And Commit Conventions

- When writing, reviewing, staging, committing, branching, pushing, or opening PRs, use the Codex skill `convencoes-git-commits`.
- When defining, applying, or reviewing AI-assisted contribution policy, pull requests, contribution docs, or AI disclosure metadata, use the Codex skill `ai-contribution-governance`.
- Write all Git-facing content in English, including commit messages, branch names, PR titles/descriptions, tags, releases, changelog entries, squash/rebase messages, and trailers.
- Branch names must follow Git convention prefixes such as `feature/`, `bugfix/`, `docs/`, `test/`, `refactor/`, `chore/`, `perf/`, or `ci/`; do not use the default Codex app `codex/` branch prefix in this repository.
- Use Conventional Commits, matching the existing history, for example `feat(auth): Add permission requests` or `docs(memory): Update project state`.
- Keep commit subjects imperative, specific, and at most 50 characters after the type/scope prefix when practical.
- Before creating a commit, inspect `git status --short`, `git diff`, and `git diff --cached`; stage only related changes and keep commits atomic.
- Do not include unrelated user changes, local reports, generated files, secrets, `.env` files, local databases, virtualenvs, coverage output, or NiceGUI local storage.
- Run the relevant tests or checks before committing; if they are skipped, state why in the final response.

## AI Contribution Governance

- AI tools are assistants, not authors, reviewers, approvers, signers, or legal certifiers.
- Meaningful AI assistance must be disclosed in PR metadata or with an `Assisted-by:` trailer such as `Assisted-by: Codex:GPT-5.5`.
- AI agents must not add `Signed-off-by:` trailers. Only a human contributor can certify DCO-style responsibility.
- A human must review, understand, validate, and take responsibility for every AI-assisted change before submission.
- For substantial generated content, include a short prompt/tool summary and identify the generated or assisted areas.
- Challenge oversized, under-tested, architecture-incoherent, security-sensitive, or unexplained generated patches.
- Security-sensitive changes require extra scrutiny when they touch auth, authorization, OAuth2/OIDC, JWT, LNURL Auth, secrets, cryptography, sessions, migrations, deployment, CI/CD, or supply chain behavior.
- Keep AI-assisted patches small, explainable, reproducible, testable, and traceable.

## Conventions

- Use `specs/` for Spec-Driven Development. For behavior changes, create or update a spec before implementation when the change affects auth, OIDC/OAuth2 behavior, LNURL-auth, persistence, security, user flows, or public contracts.
- Keep `docs/priority-execution-backlog.md` as an active temporary queue. Remove completed tasks from it and summarize them in `docs/priority-execution-history.md`.
- Use `DESIGN.md` as the source of truth for SatOIDC interface conventions before changing NiceGUI pages.
- Keep standalone Markdown discoverable through an index. Link new docs from `README.md`, `docs/README.md`, `specs/index.md`, or `agent-memory/index.md` as appropriate.
- Follow the existing FastAPI plus NiceGUI routing style.
- For NiceGUI UI behavior, check the official framework docs first: https://nicegui.io/ and https://nicegui.io/documentation.
- Do not add custom JavaScript, `ui.run_javascript`, direct DOM manipulation, or browser storage workarounds for NiceGUI screens unless the user explicitly authorizes it. Prefer NiceGUI native APIs, bindings, events, refreshable components, storage abstractions, Quasar props, and Tailwind/classes.
- Keep protocol behavior aligned with OpenID Connect, OAuth2, Authlib, and LNURL-auth semantics.
- Authlib server helpers are synchronous in the current 1.7.x line used here. Keep Authlib database operations behind the sync session boundary and call them from async routes through threadpool helpers instead of mixing async SQLAlchemy sessions into Authlib callbacks.
- Prefer existing helpers in `satoidc/satoidc/auth/`, `satoidc/satoidc/models/`, and `satoidc/satoidc/validators.py` before adding new abstractions.
- For schema changes, generate Alembic migrations with `cd satoidc; poetry run alembic revision --autogenerate -m "<message>"` against a database at the current head, then edit only the minimum necessary for dialect-specific fixes, data backfills, enum handling, or constraint details. Do not hand-write a new migration from scratch unless the user explicitly asks for that exception.
- Keep route-level UI changes consistent with the existing NiceGUI component and class patterns.
- Add focused tests for protocol, auth, validation, persistence, and time-sensitive behavior. Use `freezegun` for expiration windows and clock-dependent token/challenge behavior.
- Keep browser e2e tests marked with `e2e`; the default `task test` command intentionally excludes them.
- Before implementing new test layers, follow `specs/features/quality-testing/` for markers, task commands, dependencies, fixtures and directory layout.

## UI Verification

- After meaningful NiceGUI changes, run `cd satoidc; poetry run task run` and inspect the affected route on desktop and mobile widths.
- When the route is covered by e2e smoke checks, run `cd satoidc; poetry run task test_e2e` after installing Chromium with `task playwright_install`.
- Check for text overlap, clipped controls, broken QR rendering, unreadable contrast, and missing empty/error states.
- For auth and OIDC UI changes, verify direct navigation and redirected flows.

## Safety And Boundaries

- Do not commit secrets, `.env` files, local databases, virtualenvs, coverage output, or NiceGUI local storage.
- Treat `satoidc/database.db` and `satoidc/satoidc.db` as local runtime data.
- Do not rewrite migrations or generated artifacts unless the task explicitly requires it.
- Before changing auth, token, redirect, client registration, or key material handling, inspect the surrounding tests and OIDC expectations.

## Agent Memory

- Use `agent-memory/` for durable project memory.
- Search memory before reading many source files.
- Record only stable decisions, validated commands, recurring pitfalls, and open questions.
- Key memory entry points are `agent-memory/index.md`, `agent-memory/architecture.md`, and `agent-memory/risks.md`.
