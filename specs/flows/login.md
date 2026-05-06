# Login Flow

Status: draft
Updated: 2026-05-06

## Password Login

1. User opens `/login`.
2. Page creates `login_nonce` in session.
3. User submits identifier, password, redirect target, and nonce.
4. Server checks nonce.
5. Server resolves user by email or login.
6. Server verifies password hash.
7. Server stores `request.session["user_id"]`.
8. Server redirects to submitted `redirect_to`.

## LNURL Login

1. User opens QR dialog on `/login`.
2. Page creates `LnurlAuthChallenge(action="login")`.
3. Wallet signs `k1` and calls LNURL callback.
4. Callback emits event with `k1` and user id.
5. Login page stores the event user id under a transient nonce.
6. Browser navigates to `/auth/lnurl/redirect`.
7. Redirect route moves the transient user id into the session.

## Risks To Resolve

- Password login must sanitize `redirect_to` with `safe_redirect`.
- Session nonce and LNURL transient storage should be tested for replay and cross-session behavior.
