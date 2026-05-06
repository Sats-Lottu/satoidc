---
title: Project State
tags:
  - agent-memory/state
type: state
project: satoidc
status: active
updated: 2026-05-06
---

# Project State

SatOIDC is a Python project for an OpenID Connect provider with Bitcoin/Lightning LNURL-auth integration.

Important paths:

- `satoidc/pyproject.toml`: Poetry project configuration and taskipy commands.
- `satoidc/satoidc/__init__.py`: FastAPI app setup and NiceGUI integration.
- `satoidc/satoidc/routes/`: browser and API routes.
- `satoidc/satoidc/auth/`: OAuth2, LNURL, security, and scopes.
- `satoidc/satoidc/fastapi_oauth2/`: local FastAPI integration layer for Authlib.
- `satoidc/satoidc/models/`: SQLAlchemy models and database setup.
- `satoidc/migrations/`: Alembic migrations.
- `satoidc/DockerFile`, `satoidc/entrypoint.sh`, `compose.yaml`, `.dockerignore`, `.env.example`: production-like Docker Compose stack with PostgreSQL healthcheck, cached Poetry dependency install, non-root app runtime, migrations, setup wizard, and FastAPI startup.
- `examples/`: OIDC client examples.
- `specs/`: Spec-Driven Development workspace for feature specs, flows, contracts, and SDD decisions.
- `DESIGN.md`: SatOIDC interface guidelines for NiceGUI pages, colors, layout, components, accessibility, and visual verification.

The repository root is also the Obsidian vault root for project memory.

Documentation added after full project analysis:

- `docs/project-analysis.md`: broad repository, architecture, runtime, flows, validation, and risk analysis.
- `docs/architecture.md`: system architecture and sequence diagrams.
- `docs/known-issues.md`: prioritized technical debt.
- `specs/contracts/oidc.md`: draft OIDC contract.
- `specs/flows/authorization-code.md`, `specs/flows/login.md`, `specs/flows/lnurl-auth.md`: draft SDD flow docs.
