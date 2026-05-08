# Registration Flow

Status: draft
Updated: 2026-05-08

## Password Registration

1. User opens `/register`.
2. Page renders a standard HTML form with login, email, nickname, password, confirmation, terms acceptance, and redirect target.
3. User submits the form to `POST /register`.
4. Server validates fields and password confirmation.
5. Server rejects duplicate login or email.
6. Server stores the new user with a hashed password.
7. Server stores `request.session["user_id"]`.
8. Server redirects to submitted `redirect_to`.

## LNURL Registration

1. User opens QR dialog on `/register`.
2. Page creates `LnurlAuthChallenge(action="register")`.
3. Wallet signs `k1` and calls LNURL callback.
4. Callback creates or resolves the wallet-backed user and emits the event.
5. Register page stores the event user id under a transient nonce.
6. Browser navigates to `/auth/lnurl/redirect`.
7. Redirect route moves the transient user id into the session.

## Risks To Resolve

- Password registration must sanitize `redirect_to` with `safe_redirect`.
- Password registration should report validation and duplicate-field errors without leaking database exceptions.
