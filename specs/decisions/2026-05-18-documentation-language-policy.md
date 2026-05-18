# Repository Language Policy

## Status

- Status: implemented
- Date: 2026-05-18

## Context

SatOIDC previously contained a mix of English and Portuguese in specs,
historical reports, and planning artifacts. That made searching, reviewing, and
onboarding harder because durable repository content did not share a single
language.

AI-agent conversations are different from repository artifacts. Users should be
free to interact with Codex, Claude, Gemini, and other agents in whichever
language is most comfortable, but the persisted repository output must remain
consistent.

## Decision

English is the only language for repository content.

This applies to:

- source code identifiers;
- code comments and docstrings;
- log messages and audit-event text;
- user-facing strings committed to the repository;
- specs, contracts, flows, design docs, decisions, runbooks, reports, and
  project memory;
- tests, fixtures, example payloads, and sample data;
- configuration keys, examples, scripts, and task names;
- Git branch names, commit messages, pull request titles, pull request bodies,
  changelog entries, tags, release notes, and trailers.

Interactions with AI agents such as Codex, Claude, Gemini, and similar tools may
use any language preferred by the user. If those interactions produce files,
patches, specs, docs, code, comments, logs, or commits in the repository, the
persisted result must be written in English.

## Consequences

- New repository artifacts must be written in English.
- Existing non-English repository artifacts should be translated, replaced, or
  archived in English when touched.
- Historical files may keep their original filename for link stability, but
  their content should be English.
- If a user provides requirements in another language, the agent may discuss
  them in that language and then commit the repository artifact in English.

## Related

- `AGENTS.md`
- `docs/archive/legacy-analysis-report.md`
- `specs/index.md`
