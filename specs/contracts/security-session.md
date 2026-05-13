# Security And Session Contract

Status: draft
Area: Auth/Security
Last Updated: 2026-05-13

## Intent

Describe the current request authentication, session, password, redirect, and
permission-check behavior.

## Public Paths

`AuthMiddleware` allows requests through when the path is exactly:

- `/`
- `/register`
- `/login`
- `/logout`
- `/health`
- `/forbidden`

It also allows paths beginning with:

- `/_nicegui`
- `/oauth`
- `/api`
- `/auth/lnurl`
- `/.well-known`

All other paths require `request.session["user_id"]`.

## Missing Session Behavior

When a protected path has no session user:

1. The middleware preserves the original path and query string.
2. It redirects to `/login?redirect_to=<original>`.
3. It uses HTTP 303.

## Page-Level Permission Checks

`page_security(...)` protects selected NiceGUI pages.

Current behavior:

- Missing `user_id` redirects to `/login`.
- Invalid UUID `user_id` redirects to `/login`.
- Active permissions are loaded from `permissions`.
- Disabled permissions are ignored.
- Expired permissions are ignored.
- `root` authorizes every permission requirement.
- Default permission for `page_security()` is `root`.
- Default matching mode is `any`.
- Unauthorized users redirect to `/forbidden`.

## Passwords

Password hashing and verification use `pwdlib.PasswordHash.recommended()`.

Current flows using password hashing:

- Password registration.
- Setup wizard root creation.
- Profile password change.

## Redirect Safety

`safe_redirect(...)` accepts only relative paths beginning with `/` and rejects:

- empty values.
- host-relative URLs beginning with `//`.
- absolute external URLs.
- bare relative strings such as `profile`.

Current behavior:

- Registration sanitizes `redirect_to`.
- Login currently redirects to submitted `redirect_to` after password login
  without applying `safe_redirect`; this is a known gap.

## CSRF And Flow Nonces

Current nonce/token protections:

- `/login` generates `login_nonce` and validates it on `POST /login`.
- `/register` uses a nonce to associate LNURL redirect temp storage.
- `/authorize` stores `csrf_token` and validates it on `POST /oauth/authorize`.

## Acceptance Criteria

- Given a protected path without a session, when requested, then the user is
  redirected to `/login` with `redirect_to`.
- Given an invalid session UUID on a page protected by `page_security`, when
  requested, then the user is redirected to `/login`.
- Given an active root permission, when any protected permission is required,
  then access is allowed.
- Given disabled or expired permissions, when access is checked, then those
  permissions do not authorize access.
- Given registration receives an unsafe redirect, then it redirects to `/`.
