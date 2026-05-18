# Phase 3: Setup Wizard UI

Status: open
Priority: P2/P3
Recommended agents: NiceGUI frontend, backend security

## Task 3.6: Build Interactive Setup Wizard MVP

1. Clear task name: Build the interactive setup wizard MVP.
2. Technical objective: guide a fresh instance from incomplete setup to usable
   root/admin login.
3. Detailed scope: diagnostics, instance configuration, initial admin, final
   masked review, apply, completion, and lock public setup after completion.
4. Required inputs: `specs/features/setup-wizard/spec.md`,
   `specs/flows/setup-wizard.md`, `DESIGN.md`, setup config/bootstrap tasks.
5. Expected outputs: NiceGUI wizard flow and e2e tests.
6. Dependencies: Tasks 3.1, 3.2, 3.3, 3.4, and 3.5.
7. Completion criteria: fresh interactive deployment shows wizard; completed
   setup persists state and redirects to login/admin; public setup is blocked
   after completion.
8. Validation/test criteria: setup integration tests and Playwright desktop and
   mobile coverage.
9. Recommended specialized agent: NiceGUI setup wizard agent.
10. Priority: P2.
11. Estimated complexity: L.
12. Technical risks: exposing public setup after completion; leaking secrets in
    review UI.
13. Potentially affected files/components: `setup_wizard/`, `routes/`,
    `tests/setup/`, `tests/e2e/`.
14. Contracts/interfaces involved: Setup Wizard spec, Security And Session
    Contract.
15. Integration notes: avoid custom JavaScript; use native NiceGUI components.

### Subtasks

- Render diagnostics step.
- Render instance/admin steps.
- Implement final masked review.
- Apply configuration atomically through setup services.
- Block public setup after completion.
- Add e2e coverage.

## Task 3.7: Add Admin-Only Reconfiguration Mode

1. Clear task name: Add authenticated setup reconfiguration mode.
2. Technical objective: allow admins to review or change wizard-owned settings
   after bootstrap without exposing public setup.
3. Detailed scope: admin-only route, read-only env-controlled fields, explicit
   confirmation for high-impact settings, audit events.
4. Required inputs: setup wizard spec, page security helpers, completed
   interactive wizard.
5. Expected outputs: `reconfigure_mode` flow and tests.
6. Dependencies: Task 3.6 and administrative audit coverage recommended.
7. Completion criteria: only authenticated admins/root users can enter
   reconfiguration; env-controlled values cannot be overwritten from UI.
8. Validation/test criteria: negative unauthenticated tests and admin e2e.
9. Recommended specialized agent: frontend/backend security agent.
10. Priority: P3.
11. Estimated complexity: L.
12. Technical risks: overwriting environment-controlled production settings.
13. Potentially affected files/components: `setup_wizard/`,
    `auth/permissions.py`, `routes/`, tests.
14. Contracts/interfaces involved: Runtime Configuration Contract, Setup Wizard
    spec, Security And Session Contract.
15. Integration notes: leave secret rotation out unless a dedicated rotation
    spec exists.

### Subtasks

- Add admin route guard.
- Render env-controlled fields as locked/read-only.
- Add confirmation for issuer/public URL/signing backend changes.
- Add audit/log events.
- Add e2e coverage.

