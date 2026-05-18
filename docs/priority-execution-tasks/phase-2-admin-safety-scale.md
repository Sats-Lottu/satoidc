# Phase 2: Admin Dashboard Safety And Scale

Status: open
Priority: P1/P2
Recommended agents: NiceGUI frontend, backend services

## Task 2.1: Add Typed Confirmation For OAuth Client Deletion

Status: completed on 2026-05-18. Keep this section for traceability until the
remaining phase tasks are completed.

1. Clear task name: Add destructive confirmation for OAuth client deletion.
2. Technical objective: prevent accidental deletion of OAuth clients.
3. Detailed scope: update the dashboard delete dialog so the final destructive
   control is disabled until the admin or owner types the expected client name
   or client id.
4. Required inputs: `specs/features/admin-dashboard-safety-scale/spec.md`,
   `satoidc/satoidc/routes/dashboard.py`,
   `satoidc/satoidc/services/oauth_clients.py`, `DESIGN.md`.
5. Expected outputs: safer UI, refreshed list behavior, and tests.
6. Dependencies: none; structured logging/audit is recommended if available.
7. Completion criteria: client deletion cannot be submitted until confirmation
   text matches exactly.
8. Validation/test criteria: unit tests for service behavior and Playwright e2e
   for disabled/enabled delete control.
9. Recommended specialized agent: NiceGUI frontend agent.
10. Priority: P1.
11. Estimated complexity: S.
12. Technical risks: stale dashboard state after deletion.
13. Potentially affected files/components: `routes/dashboard.py`,
    `services/oauth_clients.py`, `tests/e2e/`.
14. Contracts/interfaces involved: Client Registration Flow, Admin Dashboard
    Safety And Scale spec.
15. Integration notes: use this as the pattern for future destructive actions.

### Subtasks

- [x] Identify the stable confirmation string.
- [x] Update the NiceGUI dialog.
- [x] Keep the destructive button disabled until exact match.
- [x] Refresh affected dashboard state after deletion.
- [x] Add focused e2e coverage.

## Task 2.2: Add Server-Side Dashboard Pagination Services

Status: completed on 2026-05-18. Keep this section for traceability until the
remaining phase task is completed.

1. Clear task name: Add server-side pagination services for admin dashboard.
2. Technical objective: replace fixed query limits with paginated service
   helpers.
3. Detailed scope: users, OAuth clients, permission requests, and metadata
   needed for pagination controls.
4. Required inputs: `routes/dashboard.py`, `models/database.py`,
   `services/oauth_clients.py`, permission request service code.
5. Expected outputs: page query helpers returning items, page, page size, total,
   and error states.
6. Dependencies: none.
7. Completion criteria: dashboard route no longer owns heavy query logic for
   the paginated sections.
8. Validation/test criteria: unit tests with more rows than page size, empty
   pages, and permission scoping.
9. Recommended specialized agent: backend persistence/service agent.
10. Priority: P2.
11. Estimated complexity: M.
12. Technical risks: breaking admin/developer scoping.
13. Potentially affected files/components: new or existing `services/` module,
    `routes/dashboard.py`, tests.
14. Contracts/interfaces involved: Database Contract, Permission Requests spec.
15. Integration notes: keep service API stable so the UI agent can work in
    parallel after the DTO is defined.

### Subtasks

- [x] Define pagination DTO.
- [x] Add user list query.
- [x] Add OAuth client list query.
- [x] Add permission request list query.
- [x] Add tests for counts and boundaries.

## Task 2.3: Add Responsive Pagination UI

Status: open.

1. Clear task name: Add responsive admin dashboard pagination UI.
2. Technical objective: let admins navigate large lists without horizontal
   overflow or fixed limits.
3. Detailed scope: page controls, page-size handling, empty/loading/error
   states, mobile and desktop behavior.
4. Required inputs: Task 2.2 services, `DESIGN.md`, NiceGUI docs,
   `tests/e2e/`.
5. Expected outputs: responsive pagination controls and e2e coverage.
6. Dependencies: Task 2.2.
7. Completion criteria: admin can navigate between pages and no list depends on
   an un-navigable fixed limit.
8. Validation/test criteria: Playwright desktop and mobile viewport checks.
9. Recommended specialized agent: NiceGUI frontend agent.
10. Priority: P2.
11. Estimated complexity: M.
12. Technical risks: NiceGUI refresh state drift; clipped controls on mobile.
13. Potentially affected files/components: `routes/dashboard.py`,
    `routes/ui_components.py`, `tests/e2e/`.
14. Contracts/interfaces involved: Admin Dashboard Safety And Scale spec.
15. Integration notes: avoid custom JavaScript; use NiceGUI-native state and
    components.

### Subtasks

- Render controls from pagination DTO.
- Add empty and error states.
- Add mobile-friendly list/table behavior.
- Add e2e tests for page navigation.
