---
name: SatOIDC Product Design System
version: 2
updated: 2026-05-07
stack:
  ui: NiceGUI
  component_runtime: Quasar Framework
  styling: Tailwind utility classes plus NiceGUI global defaults
brand:
  primary: "#3874C8"
  lightning: "#F97316"
  accent: "#38BDF8"
  background: "#070B16"
  surface: "#111827"
  border: "#263244"
  text: "#F8FAFC"
  muted: "#94A3B8"
  success: "#16A34A"
  danger: "#DC2626"
---

# SatOIDC Product Design System

SatOIDC is an OpenID Connect identity provider with Bitcoin/Lightning LNURL-auth. Its interface must feel like a secure developer-facing SaaS product: precise, modern, dark, technical, and calm. It should not look like a default NiceGUI/Quasar demo or a generic admin CRUD.

This document is the visual contract for all NiceGUI screens in this repository. Follow it before editing `satoidc/satoidc/routes/`.

## Design Direction

The product should resemble a focused SaaS console in the family of Linear, Supabase, Vercel, Stripe Dashboard, and OpenAI platform UI, adapted to identity/security workflows.

Use these qualities:

- Dark premium surface with subtle depth, not flat black.
- Compact, confident typography with clear hierarchy.
- Restrained color: blue for identity/platform, orange for Lightning actions, green/red only for state.
- Spacious layouts with dense information where it matters.
- Smooth microinteractions that signal quality without distraction.
- Developer-console clarity: tables, forms, consent review, QR actions, profile and client management must be easy to scan.

Avoid these qualities:

- Default Quasar look.
- Bright solid-blue header bars across every screen.
- Decorative card grids for operational workflows.
- Heavy gradients, glowing buttons, oversized rounded controls, or marketing UI inside dashboards.
- CSS scattered through individual routes.
- Inline `.style(...)` unless there is no NiceGUI/Tailwind/Quasar alternative.

## Implementation Strategy

Prefer global UI configuration first, then shared components, then route-level Tailwind classes.

Use this order:

1. Global theme in `satoidc/satoidc/ui_theme.py`:
   - `ui.add_head_html` for global Quasar polish that Tailwind cannot reach.
   - `ui.button.default_props`, `ui.input.default_props`, `ui.card.default_classes`, and related defaults.
   - `nicegui_app.config.quasar_config` for brand colors.
2. Shared primitives in `satoidc/satoidc/routes/ui_components.py`:
   - app header, page shell, auth shell, card, section title, footer.
   - repeatable dashboard/content patterns.
3. Route files:
   - layout composition, content, and flow-specific behavior only.
   - local Tailwind utility classes are allowed for layout and state, not for reinventing the theme per page.

Do not solve recurring visual problems inside each page. If the same class pattern appears three times, move it to a helper or global default.

## Color System

Base palette:

- Background: `bg-slate-950` or `#070B16`.
- Elevated surface: `bg-slate-900/80`.
- Secondary surface: `bg-slate-900/60` or `bg-white/5`.
- Border: `border-slate-700/60` or `border-white/10`.
- Primary text: `text-slate-50`.
- Secondary text: `text-slate-400`.
- Primary action: Quasar primary `#3874C8`.
- Lightning action: Quasar secondary/orange `#F97316`.
- Accent/focus: `#38BDF8`.
- Success: `text-emerald-400`, `color=green` when using Quasar props.
- Danger: `text-red-400`, `color=negative` for destructive states.

Use subtle background depth through global CSS only. A radial background is acceptable if it remains low contrast and does not create decorative orbs as page content.

## Typography

Use the NiceGUI/system sans-serif stack. Do not add a custom font unless the whole product adopts it.

Scale:

- Page hero title: `text-4xl font-bold`, home page only.
- Page title: `text-2xl font-bold`.
- Section/card title: `text-xl font-semibold`.
- Body: default 16px.
- Caption/helper: `text-sm text-slate-400`.
- Long technical values: `text-sm break-all`.

Rules:

- Do not scale font with viewport width.
- Keep letter spacing default.
- Avoid all-caps labels.
- Prefer short headings and precise supporting text.

## Layout

Use full-width dark page shells with constrained content:

- Auth forms: `max-w-lg`.
- Consent cards: `max-w-lg`.
- Create/edit forms: `max-w-2xl`.
- Operational dashboards: `max-w-5xl`.
- Data-heavy future dashboards: may use `max-w-6xl`.

Spacing:

- Page content: `px-4 py-8 md:px-6 md:py-10`.
- Card padding: `p-5` for normal cards, `p-6` for major summary cards.
- Gaps: `gap-4` inside forms/cards, `gap-6` between page sections.

Responsive behavior:

- Mobile screens stay single-column.
- Dashboard grids use `max-md:grid-cols-1`.
- Header navigation collapses to menu on mobile.
- Tables either wrap cells or scroll horizontally; never allow viewport overflow.
- Long IDs, redirect URIs, pubkeys, LNURLs, and token-like values must use `break-all`.

## Components

### Header

Use a top-level `ui.header`; NiceGUI layout elements must not be nested inside `ui.column`.

Header visual:

- `bg-slate-950/75`
- `border-b border-white/10`
- `backdrop-blur-xl`
- compact vertical padding

Brand:

- Logo plus `SatOIDC`.
- `Sat` in white, `OIDC` in accent blue.
- Header brand should be clickable and return home.

Navigation:

- Use icon+label buttons for primary nav on desktop.
- Use `ui.menu` on mobile.
- Keep profile/logout under a dropdown for authenticated screens.

### Buttons

Global defaults should remove the stock Quasar feel:

- `unelevated no-caps`
- `rounded-lg`
- `transition-all duration-200`
- subtle hover shadow and slight translate

Usage:

- One primary action per form.
- Secondary actions use `outline`.
- Lightning actions use orange.
- Destructive actions use negative/red.
- Use icons for clear actions: `login`, `logout`, `save`, `close`, `edit`, `mail`, `lock`, `link`, `link_off`, `dashboard`, `qr_code`, `add`.

Do not use oversized marketing buttons inside dashboards.

### Cards And Panels

Cards should feel premium but restrained:

- `bg-slate-900/80`
- `border border-slate-700/60`
- `rounded-lg`
- `backdrop-blur-xl`
- `shadow-2xl shadow-black/20`

Use cards for forms, modals, summary panels, and repeated data items. Do not nest cards inside cards. Use sections, rows, grids, and tables for structure.

### Inputs And Forms

Global defaults:

- `outlined dense`
- focus color `info` / accent blue
- modern focus ring through global CSS

Form rules:

- Every input needs a label.
- Preserve password toggle behavior.
- Put validation near the control or in concise notifications.
- URL, redirect, client, token, and scope fields need validation before persistence when business logic exists.

### Tables

Tables should feel like a modern SaaS console:

- Flat/bordered table props.
- Transparent/elevated card styling through global CSS.
- Subtle header background.
- Row hover state.
- Wrapped technical values.
- Search/filter controls above or inside the table panel.

Avoid fake placeholder rows in committed UI. Empty states should be explicit and useful.

### Dialogs

Dialogs should be centered, compact, and visually consistent with cards. Use clear title, concise content, and explicit close/cancel actions. QR dialogs must include a copyable text fallback.

### QR And LNURL

QR blocks require stable dimensions: `w-64 h-64`.

The UI must provide:

- Wallet action link.
- Copyable LNURL text with `break-all`.
- Refresh behavior for challenge expiry.
- Orange or neutral visual emphasis for Lightning flows.

## Screen Patterns

### Home

Home can be slightly more spacious than operational screens. It should clearly introduce SatOIDC and provide login/register actions. Avoid generic marketing sections unless content is real.

### Login And Register

Use `auth_shell()` and a single centered form card. Keep the QR action as a floating action button and QR dialog. Avoid split-screen marketing layouts.

### Consent

Consent is a security review screen. It must:

- clearly show the requesting client name;
- group scopes with icons and descriptions;
- make allow/cancel visually distinct;
- preserve OAuth parameters as hidden form inputs.

### Profile

Profile is an account console, not a settings marketing page. Use summary card, two-column desktop layout, single-column mobile layout, clear wallet state, and direct dashboard links based on permissions.

### Developer Dashboard

Developer dashboard should prioritize client management:

- Page title and concise subtitle.
- Primary `New Client` action.
- Searchable table for client overview.
- Empty state with action.
- Client details in compact panels when needed.

### Admin Dashboard

Admin dashboard should prioritize pending requests and review actions. Future versions should replace static placeholder rows with real permission request data.

## Accessibility And Quality Bar

Every meaningful UI change must pass:

- no clipped controls;
- no horizontal overflow at mobile width around 390px;
- readable contrast on dark surfaces;
- focus states visible;
- no blank QR areas;
- no console errors in e2e smoke checks;
- no stock-looking default controls where global defaults should apply.

Run:

```powershell
cd satoidc
poetry run ruff check satoidc
poetry run task test
poetry run task test_e2e
```

For visual changes, also run the app and inspect desktop and mobile widths:

```powershell
cd satoidc
poetry run task run
```

## Current Design Debt

- Profile actions such as nickname/email/password/wallet changes still use placeholder notifications.
- Admin dashboard permission requests are static placeholder content.
- Client creation needs stronger validation and post-create credential display.
- Auth and dashboard screens need authenticated visual screenshots in future e2e coverage.
