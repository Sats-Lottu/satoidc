---
title: Decisions
tags:
  - agent-memory/decision
type: decision
project: satoidc
status: active
updated: 2026-05-22
---

# Decisions

- 2026-05-22: Treat the v1 LNURL callback action set as closed to `register`, `login`, and `link`. The removed stateless `auth` action must not be reintroduced without a dedicated spec, route tests, and security review.
- 2026-05-22: Treat wizard-owned mutable settings as database-backed non-secret runtime configuration loaded after env and `_FILE` sources. Database URLs, app/OIDC secrets, Transit tokens, SMTP passwords, bootstrap admin credentials, OAuth client secrets, and OIDC private keys remain deployment-owned or feature-owned.
- 2026-05-22: Treat current OAuth/OIDC endpoint paths as stable for v1: `/authorize`, `/oauth/authorize`, `/oauth/token`, `/oauth/userinfo`, `/oauth/introspect`, `/oauth/revoke`, `/.well-known/openid-configuration`, and `/.well-known/jwks.json`.
- 2026-05-22: Treat dynamic client registration, device code, client credentials, implicit, and hybrid flows as out of scope for v1 unless a dedicated spec is approved.
- 2026-05-22: Treat local database files as disposable development artifacts. Canonical project state must come from migrations plus seed/setup workflows so environments are reproducible and consistent.
- 2026-05-22: After persistent OIDC key rotation is implemented, time-sensitive OIDC token tests must validate signed JWT `exp` end-to-end with real signing, JWKS key resolution, expiration, and expired-token rejection.
- 2026-05-22: Treat NiceGUI pages as UI composition only for v1. State-changing application logic should live in services and explicit command endpoints with clear HTTP method semantics, while SatOIDC remains a session-based server app rather than a stateless public REST API.
- 2026-05-18: Consolidate Setup Wizard requirements under `specs/features/setup-wizard/spec.md`. Keep `specs/features/application-setup/spec.md` only as a superseded historical record of the implemented bootstrap slice, and use `specs/decisions/2026-05-18-setup-wizard-spec-consolidation.md` to record the rationale.
- 2026-05-18: Use English for all repository content, including code, comments, log messages, specs, docs, tests, examples, project memory, and Git-facing artifacts. AI-agent conversations with Codex, Claude, Gemini, and similar tools may use any language the user prefers, but persisted repository outputs must be English.
- 2026-05-17: Use async `httpx` for SatOIDC outbound HTTP/web requests. Keep `httpx` as a direct Poetry dependency and avoid adding new production `urllib.request`, `http.client`, or synchronous HTTP call sites for web requests.
- 2026-05-17: Generate new schema migrations with `poetry run alembic revision --autogenerate -m "<message>"` against a database at the current repository head, then edit only the minimum necessary for dialect-specific fixes, data backfills, enum handling, or constraint details.
- 2026-05-16: Track application setup bootstrap as a dedicated feature spec. Future setup work should make startup validate or generate required owned runtime values before the main app starts, while keeping Coolify-managed environment variables in Coolify.
- 2026-05-16: Use GitHub Actions plus Coolify for CI/CD. CI runs Ruff, the default non-e2e test suite, and Docker image build on pushes and pull requests; CD triggers the Coolify deploy webhook after successful `main` CI and keeps production runtime variables in Coolify.
- 2026-05-06: Use `satoidc` as the Obsidian vault for this project. If the vault is not registered in Obsidian, initialize the repository itself as the vault root.
- 2026-05-06: Keep project memory in root `agent-memory/` so agents can discover it without scanning implementation directories.
- 2026-05-06: Keep `AGENTS.md` as the canonical agent instruction file. Add tool-specific adapters only if a tool requires them later.
- 2026-05-06: Adopt a `specs/` folder for Spec-Driven Development, targeting a spec-anchored workflow where specs and implementation evolve together.
- 2026-05-06: Add `DESIGN.md` because SatOIDC has a browser-facing NiceGUI interface and needs stable UI conventions.
- 2026-05-06: Prefer `python:3.11-slim` over Alpine for the application image to reduce native dependency friction for packages such as `psycopg`, `cryptography`, NiceGUI, and Uvicorn.
- 2026-05-06: Compose should expose SatOIDC on `${SATOIDC_PORT:-8000}` and wait for PostgreSQL health before running migrations.
- 2026-05-06: Track OIDC signing key lifecycle as a dedicated feature spec at `specs/features/oidc-key-rotation/`; prefer Vault Transit for the final cryptographic backend, with encrypted private-key storage acceptable only as an MVP fallback.
- 2026-05-07: Rework `DESIGN.md` as the canonical SatOIDC product design system for premium NiceGUI/Quasar/Tailwind SaaS UI. Future interface changes should update global NiceGUI defaults and shared primitives before local route styling.
- 2026-05-07: Add reusable Codex skill `nicegui-premium-design` at `C:\Users\luss1\.codex\skills\nicegui-premium-design\` for NiceGUI redesign work, including global theme workflow, shared primitive patterns, Tailwind recipes, and verification checklist.
- 2026-05-08: NiceGUI UI behavior must use the official NiceGUI documentation first and prefer native NiceGUI APIs. Custom JavaScript, direct DOM manipulation, and manual browser storage workarounds require explicit user authorization.
- 2026-05-08: Keep Pydantic request/form schemas in `satoidc/satoidc/schemas/`. Route modules should import schemas from that package instead of defining them inline; legacy schema import paths may stay as compatibility shims.
- 2026-05-08: Keep browser-facing NiceGUI pages focused on rendering and move persistence/session behavior into FastAPI endpoints when a route has form submission behavior, as done for `POST /register`.
- 2026-05-08: Use `pragma: no cover` only for UI rendering glue, compatibility shims, or defensive branches that are not useful unit-test targets; maintain behavior coverage through focused unit/integration tests and visual coverage through Playwright e2e smoke tests.
- 2026-05-08: Treat `page_security` as authorization logic rather than UI glue. Keep it covered by focused tests and delegate database permission loading plus request authorization to testable helpers.
- 2026-05-08: SatOIDC theme changes should prefer NiceGUI `ui.colors(...)`, `default_props`, `default_classes`, and shared Tailwind class helpers. Do not use broad CSS injection through `ui.add_head_html` for normal visual theming.
- 2026-05-08: Use the shared `responsive_grid()` helper for route grids instead of `ui.grid(columns=...)` when mobile collapse is required. The helper emits Tailwind grid classes on a plain element.
- 2026-05-13: Keep global header utilities on the right side: navigation first, then theme toggle, then account menu. Signed-in home actions should use the account menu and profile/dashboard/logout actions instead of public login/register CTAs.
- 2026-05-13: Client registration must validate metadata before persistence and show generated credentials once after creation instead of redirecting immediately.
- 2026-05-13: LNURL callback attempts should consume their challenge even when signature validation fails. This is a replay-defense behavior; the implementation uses the `consumed` field to avoid implying successful signature verification.
- 2026-05-13: Implement OIDC signing key rotation MVP with encrypted database-backed RSA private JWKs, stable `kid` values in JWKS, `active`/`validating`/`retired` states, and `admin` or `root` authorization for manual key lifecycle endpoints. Vault Transit remains the preferred future backend.
- 2026-05-13: Treat `developer` as a first-class `PermissionsEnum` value. Developer access includes `developer`, `admin`, and `root`; `root` remains all-powerful through the centralized authorization helper.
- 2026-05-15: Treat full browser authorization-code e2e as a priority release gate. The suite must cover a real browser redirect through consent, code exchange, ID Token, refresh token issuance, and UserInfo for both public PKCE and confidential `client_secret_post` clients.
- 2026-05-15: Preserve OAuth redirect query strings through login hidden fields without HTML entity corruption. Continue using `safe_redirect` for redirect safety, but do not encode `&` into `&amp;` inside form values that must round-trip as URLs.
- 2026-05-15: Keep Authlib bearer-token integration compatible with its current header/scope expectations: preserve an `Authorization` key in the FastAPI request adapter and pass UserInfo required scopes as a list.
- 2026-05-16: For hardened OIDC signing, design against a Vault-compatible Transit interface. Prefer OpenBao as the default self-hosted backend because it better matches SatOIDC's open-source, sovereignty, auditability, and future-project philosophy; keep HashiCorp Vault compatibility for managed service, Enterprise support, or existing Vault estates.
- 2026-05-16: Email verification/account recovery must include Testcontainers-backed email-server integration coverage, and OpenBao/Vault-compatible signing must include Testcontainers-backed OpenBao coverage for the real Transit path.
- 2026-05-16: Promote the Gemini report findings into explicit backlog/specs instead of treating the original root `relatorio.md` as a source of truth. That report was normalized and archived as `docs/archive/legacy-analysis-report.md`; durable tracked work lives in public route boundary hardening, external signing backend, route service extraction, operational observability, token load checks, LNURL shim cleanup, and report encoding/archive cleanup.
