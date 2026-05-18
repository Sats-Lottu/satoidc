# Legacy Codebase Analysis Report

> [!IMPORTANT]
> Historical archive: this report is a snapshot from an earlier analysis pass.
> Many findings were promoted into specs/backlog items and have since been
> implemented or superseded. Use `docs/known-issues.md`,
> `docs/priority-execution-history.md`, `agent-memory/project-state.md`, and
> `specs/index.md` as the current sources of truth.

## Executive Summary

SatOIDC combines OpenID Connect/OAuth2 identity-provider flows with
Bitcoin/Lightning LNURL-auth. The project uses FastAPI, NiceGUI, Authlib,
SQLAlchemy, and Alembic.

The original external analysis found a strong documentation culture and a
security-aware implementation, but also identified several production-readiness
risks. Most actionable items from that analysis were later promoted into
backlog items, specs, implementation work, or follow-up documents.

## Original Analysis Scope

The analysis covered:

- UI and API routes under `satoidc/routes/*.py`;
- authentication and OIDC code under `satoidc/auth/*.py`;
- end-to-end tests under `satoidc/tests/e2e/*.py`;
- documentation, specs, and runtime configuration files.

## Historical Findings

The original report highlighted:

- sync/async boundary complexity between Authlib, SQLAlchemy, and FastAPI;
- high coupling between NiceGUI route handlers and persistence/business logic;
- large route functions with complexity lint suppressions;
- database-backed encrypted OIDC private keys as an MVP that should evolve to a
  hardened external signing backend;
- public route boundary risks in authentication middleware;
- heavy use of UI coverage exclusions where browser e2e tests were expected to
  provide coverage.

## Current Status

The report is no longer the source of truth. Relevant findings were moved into
durable artifacts:

- public route boundary hardening;
- external OpenBao/Vault-compatible signing backend;
- route service extraction;
- operational observability;
- quality testing expansion;
- LNURL schema cleanup;
- setup/bootstrap hardening;
- reverse-proxy deployment guidance.

See `specs/index.md`, `docs/known-issues.md`, and
`docs/priority-execution-history.md` for the current state.

## Retained Value

This archive remains useful as historical context for why several specs and
backlog items were created. It must not be used to infer current bugs without
checking the current code, tests, and active specs.
