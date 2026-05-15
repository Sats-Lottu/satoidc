---
title: UI Screen Index
tags:
  - agent-memory/state
  - ui/index
type: state
project: satoidc
status: active
updated: 2026-05-15
---

# UI Screen Index

Use this note before changing SatOIDC NiceGUI screens. The visual source of truth is [[../DESIGN|DESIGN.md]], supported by the reusable Codex skill `nicegui-premium-design`.

Before implementing NiceGUI UI behavior, check the official docs at `https://nicegui.io/` and `https://nicegui.io/documentation`. Do not add custom JavaScript, `ui.run_javascript`, direct DOM manipulation, or manual browser storage workarounds without explicit user authorization; prefer NiceGUI native bindings, events, refreshable components, storage abstractions, Quasar props, and Tailwind/classes.

## Global UI Layer

- `satoidc/satoidc/ui_theme.py`: global NiceGUI/Quasar theme. Defines brand colors, body background, Quasar field/table/menu/dialog polish, and `default_props`/`default_classes` for buttons, inputs, textareas, selects, cards, and tables.
- `satoidc/satoidc/routes/ui_components.py`: shared UI primitives. Defines page tokens, app header, GitHub official SVG mark, desktop/mobile nav, theme toggle, page/auth shells, card helper, section title, empty state, and footer.
- `DESIGN.md`: product design system for premium NiceGUI/Quasar/Tailwind SaaS UI.

## Public And Auth Screens

- `/` in `satoidc/satoidc/routes/home.py`: public and signed-in home. Uses `app_header`, official GitHub mark in nav, product hero, public register/login actions, signed-in profile/dashboard/logout actions, and value cards for OIDC, LNURL-auth, and developer console.
- `/login` in `satoidc/satoidc/routes/login.py`: sign-in form plus floating LNURL QR action. Uses `auth_shell`, `auth_context_panel`, QR dialog, nonce-protected POST flow, password login, LNURL event redirect, and responsive two-column desktop/single-column mobile composition.
- `/register` in `satoidc/satoidc/routes/register.py`: registration form plus floating LNURL QR action and terms dialog. Uses `auth_shell`, `auth_context_panel`, client-side validators, terms acceptance, LNURL event redirect, and responsive two-column desktop/single-column mobile composition. Password account creation now happens in `POST /register`, not inside the page render callback.
- `/auth/lnurl/redirect` in `satoidc/satoidc/routes/login.py`: transient LNURL redirect page after wallet auth.
- `/forbidden` in `satoidc/satoidc/routes/forbidden.py`: public/protected access-denied screen with shared page shell/card.

## OAuth/OIDC Screens

- `/authorize` in `satoidc/satoidc/routes/authorize.py`: OAuth consent review. Must preserve OAuth query parameters as hidden form inputs, show client name, group scopes, and keep approve/deny visually distinct.
- Protocol/API routes live in `satoidc/satoidc/routes/oauth2.py`; these are not NiceGUI visual screens but affect auth/consent flows.

## Authenticated Console Screens

- `/profile` in `satoidc/satoidc/routes/profile.py`: account console. Shows profile summary, permission chips, user info, editable nickname/email/password, developer/admin dashboard links, wallet state, LNURL wallet link/relink/unlink actions, and developer access request state.
- `/dashboard/developer` in `satoidc/satoidc/routes/dashboard.py`: developer dashboard. Shows OAuth2 clients table, search, empty state, client details, edit metadata, copy ID, rotate secret, disable/enable, and delete actions.
- `/dashboard/admin` in `satoidc/satoidc/routes/dashboard.py`: admin permission request dashboard. Shows operational metrics, database-backed pending permission requests, approve/deny actions, recent developer grants, users, clients, and inactive permissions.
- `/create_client` in `satoidc/satoidc/routes/create_client.py`: OAuth2 client creation form with developer/admin access control, metadata validation, and one-time credential display.

## Current UI Debt

See [[ui-backlog]] for the detailed implementation backlog covering `/`, `/profile`, `/dashboard/admin`, `/dashboard/developer`, and `/create_client`.

- Priority UI backlog is complete as of 2026-05-15.
- Create-client still uses notifications rather than inline field-level validation messages.
- Longer-term maintenance question remains: whether profile mutations should stay as NiceGUI events or move to POST endpoints for clearer backend/API boundaries.
- Browser e2e now covers public pages, authenticated home/profile/dashboard/create-client flows, admin permission approval, and OAuth authorization-code flows.
