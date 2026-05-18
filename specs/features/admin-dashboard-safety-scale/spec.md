# Spec: Admin Dashboard Safety And Scale

## Status

- Status: review
- Owner: TBD
- Created: 2026-05-18
- Updated: 2026-05-18
- Product source:
  - `prd.md`
  - `relatorio_tecnico.md`
- Related code:
  - `satoidc/satoidc/routes/dashboard.py`
  - `satoidc/satoidc/services/oauth_clients.py`
  - `satoidc/satoidc/auth/permissions.py`
- Related specs:
  - `specs/flows/client-registration.md`
  - `specs/features/permission-requests/spec.md`
  - `specs/features/route-service-extraction/spec.md`

## Intent

Make admin and developer dashboards safer and more scalable for real
self-hosted operation.

## Context

The PRD and readiness report identify two UI/UX gaps:

- OAuth client deletion lacks strong confirmation.
- Admin lists use fixed limits and no server-side pagination.

`satoidc/satoidc/routes/dashboard.py` also still owns some admin query and
commit logic, so this spec provides a narrow route for further extraction without
triggering a broad NiceGUI rewrite.

## Scope

In scope:

- Strong confirmation for destructive OAuth client deletion.
- Server-side pagination for admin dashboard lists.
- Optional service helpers for admin permission approval/denial and paginated
  dashboard queries.
- Empty, loading, and error states for paginated dashboard sections.

Out of scope:

- Replacing NiceGUI.
- Building a public admin REST API.
- Enterprise audit-search UI.
- Multi-tenant admin isolation.

## Requirements

### Destructive Actions

- Client deletion must require typed confirmation using a stable client-facing
  identifier such as client name or client id.
- The destructive action button must stay disabled until the confirmation text
  matches.
- The dialog must clearly state the consequence and whether the action is
  reversible.
- Secret rotation must keep one-time secret display behavior and warning copy.

### Server-Side Pagination

- Admin users, OAuth clients, and permission requests must be fetchable by page
  and page size.
- Queries must return enough metadata to render pagination controls.
- Fixed `.limit(10)` or `.limit(25)` without navigation is not sufficient for
  product readiness.
- Empty states must remain useful when the current page has no rows.

### Service Boundary

- Permission request approval/denial persistence should move behind service
  helpers if it remains in route closures.
- Route code should compose UI and map domain/service errors to notifications.

## Acceptance Criteria

- Given an admin opens the client delete dialog, then the final delete control is
  disabled until the expected text is typed.
- Given an admin deletes a client after confirmation, then the client disappears
  from the list and the page refreshes without stale state.
- Given more users/clients/permission requests exist than the page size, then
  dashboard controls allow navigating between pages.
- Given a page query fails, then the operator sees a clear UI error and the
  server logs a sanitized operational event.
- Given service helpers are introduced, then focused unit tests cover approval,
  denial, and pagination behavior without Playwright.

## Test Plan

- Unit: dashboard query service and permission approval/denial helpers.
- UI/e2e: client deletion confirmation behavior.
- UI/e2e or route-level: pagination controls render and request the expected
  page.
- Regression: owner scoping and developer/admin permissions remain enforced.
