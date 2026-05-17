# Spec: Playwright UI Tests

## Status

- Status: draft
- Owner: project maintainers
- Created: 2026-05-16
- Updated: 2026-05-17
- Related code:
  - `satoidc/tests/e2e/`
  - `satoidc/tests/e2e/conftest.py`
  - `satoidc/pyproject.toml`
  - `DESIGN.md`
- Related specs:
  - `specs/features/quality-testing/spec.md`
  - `specs/flows/login.md`
  - `specs/flows/registration.md`
  - `specs/flows/profile.md`
  - `specs/flows/authorization-code.md`

## Intent

Define the browser UI test contract for SatOIDC so NiceGUI screens, OAuth
browser redirects, responsive layouts, and key user flows are verified with
Playwright.

## Context

The project already has `pytest-playwright-asyncio`, a `test_e2e` task, and
Playwright tests under `satoidc/tests/e2e/`. The e2e fixture starts a live
SatOIDC server on a random local port and uses an isolated test database.

## Scope

In scope:

- Public page smoke tests.
- Login, registration, profile, dashboard, and client-management UI flows.
- OAuth authorization-code browser flow with consent and token exchange.
- Responsive desktop and mobile viewport checks for meaningful NiceGUI changes.
- QR/dialog smoke checks for LNURL-auth UI behavior.

Out of scope:

- Pixel-perfect visual regression snapshots.
- External wallet automation.
- Third-party browser profiles, extensions, or stored cookies.

## Rules

- Browser tests must be marked `e2e`.
- The suite runs with `poetry run task test_e2e`.
- Chromium installation is handled by `poetry run task playwright_install`.
- Tests must use isolated server ports and isolated test data.
- Tests must not depend on the user's real browser, cookies, local storage, or
  `.nicegui` state.
- UI assertions should prefer accessible text, roles, labels, URLs, and visible
  state over fragile CSS selectors.
- Meaningful NiceGUI changes must include desktop and mobile viewport coverage
  when layout can change across breakpoints.

## Task Commands

- `poetry run task playwright_install`: `playwright install chromium`
- `poetry run task test_e2e`: `pytest -m e2e tests/e2e`

## Acceptance Criteria

- Given the e2e suite runs, then public pages render without server errors.
- Given `poetry run task test_e2e` runs, then only browser e2e tests under
  `tests/e2e` are selected.
- Given an authenticated user opens profile, dashboard, or client pages, then
  key controls and empty states are visible.
- Given a valid OAuth browser flow, then login, consent, redirect, token
  exchange, ID Token, refresh token, and UserInfo behavior are exercised.
- Given a responsive route is changed, then at least one desktop and one mobile
  viewport are checked.
- Given a QR/dialog route is changed, then the dialog opens and renders the
  expected visible state.

## Implementation Notes

- Keep browser fixtures in `satoidc/tests/e2e/conftest.py`.
- Prefer adding route-specific e2e tests only when unit or route tests cannot
  cover the risk.
- Avoid sleeping for UI timing when Playwright can wait for locators, responses,
  URL changes, or visible states.
