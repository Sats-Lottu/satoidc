# Spec: Email Verification And Account Recovery

## Status

- Status: implemented
- Owner: project maintainers
- Created: 2026-05-16
- Updated: 2026-05-17
- Related code:
  - `satoidc/satoidc/models/`
  - `satoidc/satoidc/routes/login.py`
  - `satoidc/satoidc/routes/register.py`
  - `satoidc/satoidc/routes/profile.py`
  - `satoidc/satoidc/auth/security.py`
  - `satoidc/satoidc/validators.py`
- Related specs:
  - `specs/flows/login.md`
  - `specs/flows/registration.md`
  - `specs/flows/profile.md`
  - `specs/contracts/security-session.md`
  - `specs/contracts/database.md`

## Intent

SatOIDC must distinguish between an email address that is merely stored on an
account and an email address that has been verified by the user. Verified email
is required before email can be used as the account recovery channel for
forgotten password or account access recovery.

The feature introduces a secure email verification lifecycle, a password reset
flow backed by single-use recovery tokens, and account safety rules for users
who authenticate by password, LNURL-auth, or both.

## Context

Current behavior stores a unique nullable `User.email`, accepts email during
registration, allows profile email changes, and includes email in OIDC UserInfo
when the `email` scope is granted. The project does not yet track whether that
email belongs to the user, nor does it provide a self-service password recovery
flow.

Because SatOIDC is an identity provider, recovery flows are security-sensitive:
they can become an account takeover path if tokens are long-lived, reusable,
logged, predictable, or if user enumeration leaks whether an email exists.

## Scope

In scope:

- Persisting email verification state separately from the email value.
- Sending a verification challenge after registration and after profile email
  changes.
- Letting authenticated users request a new verification email.
- Verifying email through a one-time token delivered by email.
- Password reset request and completion flows for accounts with verified email.
- Password setup through recovery for wallet-only accounts that have verified
  email.
- Consuming recovery and verification tokens exactly once.
- Expiring tokens after a short, configurable validity window.
- Avoiding user enumeration in public request responses.
- Focused tests for token generation, expiry, replay, enumeration resistance,
  duplicate email handling, and password update behavior.

Out of scope:

- External identity proofing beyond control of the email mailbox.
- Recovery through Lightning wallet signatures.
- Admin-assisted account recovery.
- Changing OIDC email scope semantics beyond exposing verification state when
  supported by the OIDC contract.
- Full email provider selection or production SMTP hardening, except for the
  runtime configuration needed to send messages.
- Multi-factor authentication.

## Definitions

- `unverified`: the account has an email value, but ownership was not proven.
- `verified`: the account has an email value and the latest verification token
  for that value was successfully consumed.
- `pending_verification`: a verification token exists for the current email and
  has not expired or been consumed.
- `recovery token`: a single-use token allowing a password reset or password
  setup for an account with verified email.

## User-Facing Rules

- New password registrations create users with `email_verified = false`.
- LNURL-auth registrations may still create users without email.
- Users may sign in before verifying email unless a later product policy
  explicitly requires verified email for selected actions.
- Profile email changes must reset verification state to unverified.
- Users can request a new verification message from `/profile`.
- Public recovery request screens must show the same success message whether
  the submitted email exists, is unverified, or is unknown.
- Password reset is available only for accounts whose current email is verified.
- Wallet-only users with verified email may use recovery to set an initial
  password; wallet unlink safety rules still apply after the password is set.
- If an account has neither verified email nor a linked wallet and the password
  is lost, self-service recovery is unavailable.

## Persistence Contract

Extend `User` with:

- `email_verified`: boolean, default `false`.
- `email_verified_at`: nullable timestamp.

Store email tokens in a dedicated table instead of session storage.

`EmailToken` fields:

- `id`: primary key.
- `user_id`: target user.
- `email`: normalized email the token was issued for.
- `purpose`: `verify_email` or `reset_password`.
- `token_hash`: hash of the opaque token sent to the user.
- `expires_at`: token expiration timestamp.
- `consumed_at`: nullable timestamp set when used.
- `created_at`: token creation timestamp.
- `request_ip_hash`: optional hashed request IP for abuse investigation.
- `user_agent_hash`: optional hashed user agent for abuse investigation.

Database constraints:

- Index by `user_id`, `purpose`, `expires_at`, and `consumed_at`.
- Index by `token_hash` as unique.
- Do not store raw tokens.
- Token validation must require matching `purpose`, unexpired `expires_at`,
  null `consumed_at`, and matching current `User.email`.

## Token Requirements

- Tokens must be generated from a cryptographically secure random source.
- The email must receive only the raw token or a URL containing it.
- The database must store only a hash of the token.
- Verification tokens should expire in 24 hours by default.
- Password reset tokens should expire in 30 minutes by default.
- Issuing a new token may leave older tokens in the database, but successful
  verification or recovery must consume all still-active tokens for the same
  user and purpose.
- Token consumption must happen in the same transaction as the state change it
  authorizes.
- Replayed, expired, malformed, wrong-purpose, or wrong-email tokens must fail
  without changing account state.

## Flows

### Registration Email Verification

1. User submits password registration with login, email, nickname, password,
   confirmation, terms acceptance, and redirect target.
2. Server validates fields and duplicate login/email as today.
3. Server creates the user with normalized email and `email_verified = false`.
4. Server creates a `verify_email` token for the new user's email.
5. Server sends a verification link to the email address.
6. User remains signed in after registration.
7. Profile shows a visible unverified email state and a resend action.
8. User opens the verification link.
9. Server validates and consumes the token.
10. Server sets `email_verified = true` and `email_verified_at = now`.

### Profile Email Change

1. Authenticated user opens `/profile`.
2. User changes email to a syntactically valid, unused address.
3. Server stores the normalized new email.
4. Server resets `email_verified = false` and `email_verified_at = null`.
5. Server creates and sends a new `verify_email` token.
6. Existing active password recovery tokens for the account are invalidated.
7. Profile shows the new email as unverified until the token is consumed.

### Resend Verification

1. Authenticated user opens `/profile`.
2. User selects the resend verification action.
3. Server verifies the account has an email and it is not already verified.
4. Server rate-limits resend attempts.
5. Server creates a new `verify_email` token and sends the message.
6. UI confirms that a verification message was requested.

### Request Password Reset

1. User opens `/forgot-password`.
2. User submits an email address.
3. Server normalizes the email and always returns a generic success response.
4. If the email belongs to an account and `email_verified = true`, server
   creates a `reset_password` token and sends a recovery link.
5. If the email is unknown or unverified, server sends nothing and exposes no
   difference in the public response.

### Complete Password Reset

1. User opens `/reset-password?token=<token>`.
2. Server validates the token without exposing the target account identity.
3. User submits a new password and confirmation.
4. Server validates password strength and confirmation match.
5. Server consumes the token in the same transaction that updates
   `User.password_hash`.
6. Server invalidates active reset tokens for the same user.
7. Server redirects to `/login` with a generic success state.
8. Existing browser sessions may remain valid for the first version, but the
   implementation must document this choice before marking the spec approved.

## Routes

Proposed routes:

- `GET /verify-email?token=<token>`: consume verification token and show result.
- `POST /profile/email/resend-verification`: request a new verification email.
- `GET /forgot-password`: render public recovery request page.
- `POST /forgot-password`: accept recovery request and send generic response.
- `GET /reset-password?token=<token>`: render reset form when token appears
  valid.
- `POST /reset-password`: accept token, new password, and confirmation.

All public recovery routes must be included deliberately in the authentication
middleware public path contract.

## Email Delivery Contract

The first implementation may use SMTP or a local development sender, but it
must expose a narrow internal interface:

- `send_email_verification(user, email, verification_url)`
- `send_password_reset(user, email, reset_url)`

Runtime configuration must cover:

- sender mode: disabled, console, or SMTP.
- public base URL used to build links.
- SMTP host, port, username, password, TLS mode, and from address when SMTP is
  enabled.
- token expiration settings.

When email sending is disabled, registration and profile email changes may
still create tokens, but the UI must clearly state that delivery is not
configured in development or administration contexts.

Integration coverage for the SMTP backend must use Testcontainers to start a
disposable email server through Docker. The test server must capture delivered
messages so tests can assert recipient, subject, verification/recovery link
shape, token delivery, and absence of sensitive application data in message
content.

## OIDC Claim Considerations

Current OIDC UserInfo includes `email` when the granted scope includes `email`.
After this feature, the provider should also support `email_verified` as a
boolean claim when `email` is granted.

Rules:

- `email_verified` reflects the current stored email only.
- Changing email immediately changes `email_verified` to `false`.
- ID Token inclusion is out of scope unless the OIDC contract is updated.

## Security Requirements

- Do not log raw verification or reset tokens.
- Do not include tokens in analytics, audit notes, or exception details.
- Use generic public messages for recovery requests and invalid reset tokens.
- Rate-limit verification resend and password reset requests per email and per
  source address.
- Recovery tokens must not authenticate the user for any action other than
  setting a new password.
- Reset forms must not display account login, nickname, current email, wallet
  state, permissions, client ownership, or other private account data.
- Password reset must use the existing password hashing helper.
- Redirects after verification and reset must use the existing safe redirect
  rules if a redirect target is accepted.
- Email templates must not include password hashes, session identifiers, OAuth
  tokens, LNURL private material, client secrets, or permission details.

## UI Requirements

Profile page:

- Show whether the current email is verified, unverified, or absent.
- Provide a resend verification action only when an email exists and is
  unverified.
- After email change, show the unverified state immediately.

Registration page:

- After successful registration, tell the user to verify email without blocking
  the signed-in session.

Forgot password page:

- Use a compact public form with email input.
- Always show a generic "check your email if an account can be recovered"
  response.

Reset password page:

- Show only new password and confirmation fields.
- Show expired or invalid token states without identifying the account.

## Acceptance Criteria

- Given a new password registration, when the user is stored, then
  `email_verified` is false and a verification token exists.
- Given a valid verification token for the user's current email, when consumed,
  then the user's email becomes verified and the token cannot be reused.
- Given a verification token issued for an older email, when the user changes
  email before consuming it, then consuming the old token does not verify the
  new email.
- Given an authenticated user changes email, when the update succeeds, then
  email verification state is reset.
- Given an unknown email submitted to password recovery, when processed, then
  the public response matches the response for a known email.
- Given an unverified email submitted to password recovery, when processed, then
  no reset token is created.
- Given a verified email submitted to password recovery, when processed, then a
  reset token is created and only its hash is stored.
- Given a valid reset token and strong matching password, when submitted, then
  the password hash changes and the reset token is consumed.
- Given an expired, reused, malformed, or wrong-purpose token, when submitted,
  then no account state changes.
- Given OIDC UserInfo is requested with the `email` scope, then the response can
  include `email_verified` for the current email.

## Test Plan

- Unit tests for token generation, hashing, lookup, expiry, purpose matching,
  wrong-email rejection, and single-use consumption.
- Route tests for registration verification token creation.
- Route tests for profile email change resetting verification state.
- Route tests for resend verification authorization and rate-limit behavior.
- Route tests for password recovery enumeration resistance.
- Route tests for reset token success, replay, expiry, malformed token, and weak
  password rejection.
- UserInfo tests for `email_verified` when the `email` scope is granted.
- Migration tests or database contract checks for defaults and indexes.
- Testcontainers-backed SMTP/email-server integration tests for verification
  and password recovery delivery behavior.

## Open Questions

- Should verified email become mandatory before creating OAuth clients or
  requesting developer access?
- Should password reset revoke all active sessions for the user in the first
  implementation, or is password change plus future session invalidation
  acceptable for the MVP?
- Which delivery backend should be the default for production deployments:
  SMTP only, or a pluggable provider interface from the start?
- Should email verification be required before `email` is emitted in OIDC
  UserInfo, or should clients receive both `email` and `email_verified = false`?

## Implementation Notes

Implemented on 2026-05-17:

- `User` stores `email_verified` and `email_verified_at`.
- `EmailToken` stores hashed single-use verification and reset tokens with
  purpose, expiry, consumed state, request IP hash, and user-agent hash.
- Registration creates unverified users and issues verification tokens.
- Profile email changes reset verification state and invalidate active reset
  tokens; users can request another verification message from profile.
- `/verify-email`, `/forgot-password`, and `/reset-password` implement token
  consumption, enumeration-resistant recovery requests, and password reset or
  initial password setup for verified-email accounts.
- Email delivery supports `disabled`, `console`, and `smtp` modes, with
  Testcontainers Mailpit coverage for SMTP message capture.
- OIDC UserInfo includes `email_verified` when the `email` scope is granted.
- Existing sessions are not revoked on password reset in this MVP; future
  session invalidation remains a hardening follow-up.
