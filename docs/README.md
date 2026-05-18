# Documentation Index

This folder keeps durable technical documentation for SatOIDC. Keep new Markdown files linked from this index or from `specs/index.md` so future readers do not need to scan the whole repository.

## Core Docs

- [Architecture](architecture.md): current system components, persistence boundary, and request flows.
- [Project Analysis](project-analysis.md): broad repository map, runtime stack, protocol surface, examples, validation, and risks.
- [Known Issues](known-issues.md): prioritized technical debt and production hardening items.
- [VPS Deployment](deployment/vps.md): GitHub Actions CI/CD and VPS runbook.
- [Database Support Matrix](database-support-matrix.md): SQLite/PostgreSQL
  support scope, URL pairing rules, and verification commands.
- [Local Development Troubleshooting](local-development-troubleshooting.md):
  known local setup failures and repair workflows.
- [Reverse Proxy Operations](operations/reverse-proxy.md): TLS, forwarded
  headers, and reverse-proxy rate limiting guidance for self-hosted production.
- [Priority Execution Backlog](priority-execution-backlog.md): temporary active queue for open execution work.
- [Priority Execution History](priority-execution-history.md): summary of completed backlog items removed from the active queue.
- [Backlog Priority Plan](backlog-priority-plan.md): branch-level sequencing, grouped work, commit plan, and approval questions for active backlog implementation.
- [Changes On 2026-05-08](changes-2026-05-08.md): schema package, registration endpoint, test coverage, and related bug fix.
- [Legacy Analysis Report](archive/legacy-analysis-report.md): historical external analysis snapshot; actionable items were promoted into backlog/specs and may already be implemented or superseded.

## Related Indexes

- [Project README](../README.md): public-facing overview and quick start.
- [Spec Index](../specs/index.md): Spec-Driven Development entries.
- [Agent Memory](../agent-memory/index.md): stable decisions, validated commands, current state, risks, and open questions.
