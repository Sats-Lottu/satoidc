# Documentation Index

This folder keeps durable technical documentation for SatOIDC. Keep new Markdown files linked from this index or from `specs/index.md` so future readers do not need to scan the whole repository.

## Core Docs

- [Architecture](architecture.md): current system components, persistence boundary, and request flows.
- [Project Analysis](project-analysis.md): broad repository map, runtime stack, protocol surface, examples, validation, and risks.
- [Known Issues](known-issues.md): prioritized technical debt and production hardening items.
- [V1 Legacy Sanitization Plan](v1-legacy-sanitization-plan.md): audit and
  migration plan for removing legacy, temporary, and inconsistent contracts
  before the first official release.
- [VPS Deployment](deployment/vps.md): GitHub Actions CI/CD and VPS runbook.
- [Operator Runbook](operations/runbook.md): backup, restore, upgrade,
  migration failure handling, health checks, and incident response.
- [Email Operations](operations/email.md): SMTP, console, and disabled email
  sender modes, token TTLs, validation, troubleshooting, and fallback.
- [Transit Signing Operations](operations/transit.md): OpenBao/Vault-compatible
  Transit setup, required variables, failure modes, and fallback.
- [Database Support Matrix](database-support-matrix.md): SQLite/PostgreSQL
  support scope, URL pairing rules, and verification commands.
- [OIDC Basic OP Conformance](conformance.md): disposable conformance
  environment runbook, seed data, smoke checklist, and result recording format.
- [OIDF Conformance Docker Runner](../oidf-conformance/README.md): local
  Docker Compose wrapper for the official OpenID Foundation conformance suite.
- [Setup Wizard Mutable Settings](setup-wizard-mutable-settings.md): contract
  for wizard-owned persisted settings and environment-locked configuration.
- [Local Development Troubleshooting](local-development-troubleshooting.md):
  known local setup failures and repair workflows.
- [Load Testing](load-testing.md): Locust smoke scenarios, token lifecycle seed
  requirements, and baseline result template.
- [Relying-Party Compatibility](relying-party-compatibility.md): verified and
  pending OIDC client integration matrix.
- [Reverse Proxy Operations](operations/reverse-proxy.md): TLS, forwarded
  headers, and reverse-proxy rate limiting guidance for self-hosted production.
- [Priority Execution Backlog](priority-execution-backlog.md): temporary active queue for open execution work.
- [Priority Execution Tasks](priority-execution-tasks/README.md): temporary
  multiagent task files for production-readiness execution; remove task files
  after completion and summarize outcomes in the history.
- [Priority Execution History](priority-execution-history.md): summary of completed backlog items removed from the active queue.
- [Backlog Priority Plan](backlog-priority-plan.md): branch-level sequencing, grouped work, commit plan, and approval questions for active backlog implementation.
- [Changes On 2026-05-08](changes-2026-05-08.md): schema package, registration endpoint, test coverage, and related bug fix.
- [Legacy Analysis Report](archive/legacy-analysis-report.md): historical external analysis snapshot; actionable items were promoted into backlog/specs and may already be implemented or superseded.

## Related Indexes

- [Project README](../README.md): public-facing overview and quick start.
- [Spec Index](../specs/index.md): Spec-Driven Development entries.
- [Agent Memory](../agent-memory/index.md): stable decisions, validated commands, current state, risks, and open questions.
