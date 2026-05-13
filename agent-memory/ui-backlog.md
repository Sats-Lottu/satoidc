---
title: UI Implementation Backlog
tags:
  - agent-memory/todo
  - ui/backlog
type: state
project: satoidc
status: active
updated: 2026-05-13
---

# UI Implementation Backlog

Use this note before implementing authenticated SatOIDC screens. The screen map is [[ui-index]], and the visual source of truth is [[../DESIGN|DESIGN.md]].

> [!todo] Implementation Scope
> Several UI controls already render in `/`, `/profile`, `/dashboard/admin`, `/dashboard/developer`, and `/create_client`, but they do not yet have complete state-aware behavior, backend persistence, validation, or end-to-end coverage.

## Home Page

Source: `satoidc/satoidc/routes/home.py`.

- [x] Make the `/` home page session-aware. When a user is already logged in, hide the `Login` and `Register` calls to action.
- [x] Replace anonymous auth actions with useful authenticated actions, such as `Profile`, `Developer Dashboard`, `Admin Dashboard` when permitted, and `Logout`.
- [x] Use a familiar account-entry pattern similar to Google and other identity platforms: show the signed-in user's identity or avatar/menu affordance in the header, with account actions grouped in a compact menu instead of duplicating public onboarding buttons.
- [x] Keep unauthenticated visitors on the current public onboarding path with registration and login actions.
- [ ] Add e2e coverage for both anonymous and authenticated home page rendering.

## Header And Theme Toggle

Source: `satoidc/satoidc/routes/ui_components.py`.

- [x] Reposition the theme toggle as a global header utility instead of letting it compete with primary navigation or onboarding actions.
- [x] On desktop, place theme near the right-side utility cluster, before the account/profile affordance and logout/menu actions. Carbon's UI shell guidance treats the right side as the home for global utilities such as account, search, notifications, and similar functions.
- [x] On mobile or narrow headers, collapse lower-priority actions into a compact menu if the header has too many controls. Material/Fiori top app bar guidance limits trailing actions and moves secondary actions into overflow.
- [x] Keep account/profile access more prominent than theme selection for signed-in users. The theme toggle should be easy to find, but it is a preference, not the primary account action.
- [x] Prefer an icon button or compact switch with an accessible label/tooltip, matching the existing NiceGUI native dark-mode toggle and avoiding custom JavaScript.
- [x] Validate the final header at desktop and mobile widths so theme, account, dashboard, login/register, and logout actions do not wrap awkwardly or shift primary actions.

### Header References

- [Carbon UI shell header](https://carbondesignsystem.com/components/UI-shell-header/usage/): header utilities are right-aligned global functions; account is near the far right.
- [SAP Fiori / Material 3 top app bar](https://www.sap.com/design-system/fiori-design-android/v25-8/components/m3-standard-components/top-app-bar/usage): top app bars put actions/profile on the right and use overflow when there are too many trailing actions.
- [Material Design app bar structure](https://m1.material.io/layout/structure.html#structure-app-bar): app bars reserve the right side for actions and overflow.
- [Material Design menus](https://m1.material.io/components/menus.html): overflow menus are appropriate for secondary app-bar actions such as settings and sign out.

## Profile Page

Source: `satoidc/satoidc/routes/profile.py`.

- [x] Implement nickname editing. Current `Change nickname` and `Edit nickname` controls only show a notification.
- [x] Implement email editing. Current `Change email` and `Edit email` controls only show a notification.
- [x] Implement password change. Current `Change password` controls only show a notification and need validation, password hashing, and session/security expectations.
- [ ] Implement LNURL wallet linking. Current `Link wallet` control only shows a notification.
- [x] Implement LNURL wallet unlinking. Current `Unlink wallet` control only shows a notification and needs a policy for removing `lnurl_pubkey`.
- [ ] Implement LNURL wallet relinking. Current `Relink wallet` control only shows a notification and needs replay-safe LNURL challenge handling.
- [ ] Implement developer permission request creation. Current `Request developer permissions` control only shows a success notification and does not persist a request.
- [ ] Decide whether profile mutations should use POST endpoints, NiceGUI events, or a mixed approach. Keep behavior testable and avoid custom JavaScript.

## Admin Dashboard

Source: `satoidc/satoidc/routes/dashboard.py`.

- Related spec: [[../specs/features/permission-requests/spec|Permission Requests]].
- [ ] Replace the static `Satoshi` permission request row with database-backed permission request records.
- [ ] Add a permission request persistence model or reuse an existing model if the permission taxonomy is formalized.
- [ ] Implement approve and deny actions. Current buttons render but do not mutate state.
- [ ] Record who approved or denied each request and when.
- [ ] Add empty, loading, and error states for permission request listing.
- [ ] Decide whether admin access should remain root-only through `page_security()` or use an explicit `admin` permission once the taxonomy is resolved.
- [ ] Add useful admin dashboard widgets for pending requests, recent decisions, total users, developer users, registered clients, recent clients, and disabled/expired permissions.

## Developer Dashboard

Source: `satoidc/satoidc/routes/dashboard.py`.

- [ ] Add client management actions beyond viewing: edit metadata, rotate secret, disable/delete client, and copy identifiers.
- [ ] Add secure client secret reveal/copy behavior after creation and rotation. Secrets should not be casually displayed after the creation window.
- [ ] Add validation and feedback for redirect URI and client URI issues surfaced from client creation.
- [ ] Add authenticated e2e coverage for developer dashboard rendering with zero clients and with existing clients.
- [ ] Confirm that the `developer` permission exists in the final permission taxonomy. The dashboard currently requires `page_security(permissions=["developer"])`, while the taxonomy is still open.

## Create Client Flow

Source: `satoidc/satoidc/routes/create_client.py`.

- [x] Protect `/create_client` with developer permission instead of only relying on the authenticated-session middleware.
- [x] Validate required fields, URL formats, redirect URI lines, grant types, response types, scopes, and token endpoint auth method combinations before persistence.
- [x] Normalize multiline inputs by trimming empty lines and rejecting malformed entries.
- [ ] Provide inline validation messages instead of only notifications.
- [x] Show client credentials once after creation with clear copy affordances, then navigate intentionally rather than using a timed redirect.
- [ ] Add focused tests for persistence and permission enforcement. Metadata shape and validation errors are covered by unit tests.

## Related Open Questions

- [[open-questions#Open Questions]] includes the unresolved permission taxonomy and whether `create_client` should require developer permission.
- [[risks]] tracks broader security and implementation risks that can affect these screens.
