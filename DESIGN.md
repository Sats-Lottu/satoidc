---
name: SatOIDC Interface Guidelines
colors:
  brandBlue: "#3874C8"
  brandOrange: "#F97316"
  backgroundDark: "#0B1020"
  surfaceDark: "#111827"
  borderDark: "#374151"
  textPrimary: "#F9FAFB"
  textMuted: "#9CA3AF"
  success: "#16A34A"
  danger: "#DC2626"
typography:
  body:
    fontFamily: NiceGUI default / system sans-serif
    fontSize: 16px
    lineHeight: 1.5
spacing:
  xs: 4px
  sm: 8px
  md: 16px
  lg: 24px
  xl: 32px
radius:
  control: 8px
  card: 8px
---

# SatOIDC Interface Guidelines

## Product Character

SatOIDC is an identity and authorization service. The interface should feel secure, restrained, operational, and easy to scan. Avoid marketing-heavy layouts except on the public home page. Auth, profile, dashboard, consent, and client-management screens should prioritize clarity, predictable controls, and low-friction repeated use.

## Current UI Stack

- UI is built directly in Python with NiceGUI.
- Most pages live in `satoidc/satoidc/routes/`.
- The app currently uses dark pages for most user-facing screens.
- The logo asset is `satoidc/statics/imgs/logo.png`.
- Current header brand color is `#3874c8`.

## Colors

Use a small functional palette:

- Brand blue `#3874C8`: headers, primary identity cues, selected navigation.
- Orange `#F97316`: Bitcoin/Lightning actions, primary onboarding calls to action.
- Dark background `#0B1020`: full-page dark surfaces.
- Dark surface `#111827`: panels and cards.
- Dark border `#374151`: separators and panel outlines.
- Primary text `#F9FAFB`: main text on dark surfaces.
- Muted text `#9CA3AF`: labels, captions, helper text.
- Success `#16A34A`: linked wallet, approved access, valid states.
- Danger `#DC2626`: invalid credentials, denied access, destructive actions.

Avoid making whole screens one hue. Use blue for identity/navigation, orange for Lightning/action emphasis, green/red for state, and neutral dark surfaces for content.

## Typography

- Use the NiceGUI/system sans-serif default unless a project-wide font is explicitly added.
- Body text should stay around 16px.
- Use compact headings inside cards and dashboards. Reserve large type for the public home page only.
- Do not scale font size with viewport width.
- Keep letter spacing at the default.
- Avoid long all-caps labels.

## Layout

- Use full-width page structure with constrained inner content.
- Keep auth forms around `max-w-lg`.
- Keep operational dashboards around `max-w-screen-md` to `max-w-5xl` depending on data density.
- Do not nest cards inside cards unless it is a modal/dialog.
- Prefer sections, lists, tables, and forms over decorative card grids for operational screens.
- Fixed-format elements such as QR codes, icon buttons, tables, and form controls should have stable dimensions so hover, validation, or dynamic text does not shift layout.

## Components

### Headers

- Include the SatOIDC logo and product name on primary public/auth screens.
- Keep header actions predictable: profile, logout, dashboard, login, register.
- Use icon-only buttons for common actions when the icon is familiar, with tooltips for ambiguous actions.

### Buttons

- Use primary buttons for one clear next action per form.
- Use outline buttons for secondary actions such as cancel, logout, and navigation.
- Use icons for known actions: login, logout, edit, lock, mail, link, link_off, dashboard, qr_code.
- Do not use large rounded marketing-style buttons inside dashboards.

### Forms

- Every input needs a label.
- Validation errors should be specific and placed near the failing control or shown in a concise notification.
- Password inputs should preserve the existing toggle behavior.
- Redirect, token, client, and URL fields should be validated before persistence.

### Consent Screens

- State the requesting client name clearly.
- Group scopes by meaning: identity, profile, contact, and future permissions.
- Approve and deny actions must be visually distinct.
- Do not hide OAuth parameters from the review process; preserve them in the form submission as the current code does.

### QR / LNURL

- QR code blocks should use stable square dimensions.
- Include a clear wallet action and copyable LNURL text.
- Keep challenge expiry behavior visible through refresh behavior, but avoid noisy explanatory text in the UI.
- Lightning actions should use orange or neutral styling, not danger/success colors unless representing state.

### Dashboards

- Use dense, scan-friendly tables/lists for clients, permissions, and requests.
- Avoid placeholder rows or labels in committed UI.
- Client-management screens should show client name, auth method, redirect URIs, scopes, and creation time when available.

## Accessibility

- Maintain visible focus states for interactive elements.
- Color must not be the only indicator of state; pair color with icon or label.
- Text on dark surfaces should meet contrast expectations.
- Buttons and clickable rows need at least 40px practical hit target height.
- QR code links need a text fallback for copy/paste.
- Avoid placing essential content only in tooltips.

## Responsive Behavior

- Mobile headers may collapse navigation into a menu.
- Forms should stay single-column on mobile.
- Tables should either scroll horizontally or collapse into readable rows; never allow text overlap.
- Long values such as public keys, redirect URIs, tokens, and LNURLs should wrap with `break-all` or equivalent classes.

## Visual Verification

After meaningful UI changes:

1. Run the app with `cd satoidc; poetry run task run`.
2. Check at least desktop and mobile widths.
3. Verify no text overlaps, clipped buttons, blank QR areas, or unreadable contrast.
4. Exercise the affected route, including error and empty states.
5. For auth/OIDC changes, verify both normal navigation and redirected flows.

## Known Cleanup Targets

- Normalize placeholder dashboard content.
- Replace profile placeholder notifications with real dialogs or remove unavailable actions.
- Align permission labels with the final permission model.
- Normalize README/UI encoding artifacts before copying display text into new screens.
