---
title: Decisions
tags:
  - agent-memory/decision
type: decision
project: satoidc
status: active
updated: 2026-05-06
---

# Decisions

- 2026-05-06: Use `satoidc` as the Obsidian vault for this project. If the vault is not registered in Obsidian, initialize the repository itself as the vault root.
- 2026-05-06: Keep project memory in root `agent-memory/` so agents can discover it without scanning implementation directories.
- 2026-05-06: Keep `AGENTS.md` as the canonical agent instruction file. Add tool-specific adapters only if a tool requires them later.
- 2026-05-06: Adopt a `specs/` folder for Spec-Driven Development, targeting a spec-anchored workflow where specs and implementation evolve together.
