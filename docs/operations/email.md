# SatOIDC Email Operations

Updated: 2026-05-18

SatOIDC uses email for account email verification and password recovery. The
current runtime supports three sender modes:

- `smtp`: sends messages through an SMTP server and is the production mode.
- `console`: records that a message was prepared, but does not deliver it to
  the user.
- `disabled`: skips delivery entirely.

For production, use `smtp` with a monitored mailbox/domain and an HTTPS
`EMAIL_PUBLIC_BASE_URL` that matches the public SatOIDC issuer.

## Required Settings

Current runtime settings use these environment variable names. Planned
`SATOIDC_*` aliases are documented in
[Runtime Configuration Contract](../../specs/contracts/runtime-config.md), but
are not accepted by the current settings loader yet.

| Setting | Required | Default | Notes |
| --- | --- | --- | --- |
| `EMAIL_SENDER_MODE` | optional | `disabled` | Must be `disabled`, `console`, or `smtp`. |
| `EMAIL_PUBLIC_BASE_URL` | recommended | empty | Public base URL used in `/verify-email` and `/reset-password` links. Falls back to request base URL or `OAUTH2_JWT_ISS`. |
| `EMAIL_VERIFICATION_TOKEN_TTL_SECONDS` | optional | `86400` | Verification token lifetime, 24 hours by default. |
| `EMAIL_RESET_TOKEN_TTL_SECONDS` | optional | `1800` | Password reset token lifetime, 30 minutes by default. |
| `EMAIL_TOKEN_MIN_REQUEST_INTERVAL_SECONDS` | optional | `60` | Per-user minimum interval before another active token can be issued for the same purpose and email. |
| `SMTP_HOST` | required for SMTP | empty | SMTP hostname. |
| `SMTP_PORT` | optional for SMTP | `587` | SMTP port. |
| `SMTP_USERNAME` | provider-dependent | empty | SMTP username. |
| `SMTP_PASSWORD` | provider-dependent | empty | SMTP password or app password. Current runtime does not support `_FILE` for this variable. |
| `SMTP_USE_TLS` | optional | `true` | Enables implicit TLS. Usually used with port `465`. |
| `SMTP_START_TLS` | optional | `false` | Enables STARTTLS. Usually used with port `587`. |
| `SMTP_FROM_EMAIL` | optional | `no-reply@satoidc.local` | Sender address shown in messages. |

Do not commit SMTP credentials or `.env` files. Store provider credentials in
the deployment platform secret store.

## SMTP Mode

Use SMTP when users must receive real verification and recovery links.

Example production shape:

```env
EMAIL_SENDER_MODE=smtp
EMAIL_PUBLIC_BASE_URL=https://id.example.com
EMAIL_VERIFICATION_TOKEN_TTL_SECONDS=86400
EMAIL_RESET_TOKEN_TTL_SECONDS=1800
EMAIL_TOKEN_MIN_REQUEST_INTERVAL_SECONDS=60
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=satoidc@example.com
SMTP_PASSWORD=change-me
SMTP_USE_TLS=false
SMTP_START_TLS=true
SMTP_FROM_EMAIL=no-reply@example.com
```

Provider defaults vary. Use either implicit TLS or STARTTLS according to the
provider documentation:

| Provider style | Port | `SMTP_USE_TLS` | `SMTP_START_TLS` |
| --- | --- | --- | --- |
| Implicit TLS | `465` | `true` | `false` |
| STARTTLS | `587` | `false` | `true` |
| Local Mailpit or plain relay | `1025` or provider-specific | `false` | `false` |

After changing SMTP configuration, restart the application and request one
verification message from a low-risk account. Confirm that the received link
uses the public HTTPS host, not an internal container hostname or localhost.

## Console Mode

`EMAIL_SENDER_MODE=console` is only for development and controlled testing. It
logs that a message was prepared, including recipient and subject metadata, but
it does not send the message and does not print the token URL.

Do not use console mode for production recovery. Users will not receive the
verification or password reset link.

## Disabled Mode

`EMAIL_SENDER_MODE=disabled` skips email delivery. This is acceptable for
development, demos that do not require email, or deployments that intentionally
do not offer email recovery.

Failure behavior in disabled mode:

- Email-token rows may still be created for verification or recovery requests.
- The user does not receive the raw token or URL.
- Password recovery is not usable through email.
- Existing verified email state remains unchanged.

## Token Behavior

Email tokens are generated as one-time random tokens and stored only as hashes.
The raw token appears only in the verification or reset URL at creation time.

Operational rules:

- Verification tokens default to 24 hours.
- Password reset tokens default to 30 minutes.
- Replayed, expired, consumed, wrong-purpose, or wrong-email tokens fail.
- Changing an account email resets verification state and requires a new
  verification token.
- Password reset requires the account's current email to be verified.
- Recovery request responses are intentionally enumeration-resistant and should
  not reveal whether an email exists.

Keep reset token TTLs short. Increase verification TTL only when users
regularly miss the verification window and the account-risk model accepts the
longer exposure.

## Validation

Minimum validation after enabling SMTP:

1. Confirm runtime variables:

   ```bash
   docker compose --env-file .env exec satoidc env | grep -E 'EMAIL_|SMTP_'
   ```

2. Request an email verification from the profile or registration flow.
3. Request a password reset for a verified test account.
4. Confirm both messages arrive and the links use `https://id.example.com`.
5. Follow the links once and confirm a second use fails.

The integration suite verifies SMTP delivery against Mailpit:

```bash
cd satoidc
poetry run pytest tests/integration/test_email_delivery_smtp.py
```

This test requires Docker/Testcontainers availability.

## Troubleshooting

| Symptom | Likely cause | Checks |
| --- | --- | --- |
| Startup fails with `EMAIL_SENDER_MODE` validation | Unsupported mode value | Use exactly `disabled`, `console`, or `smtp`. |
| Verification/reset page says token is invalid or expired | TTL expired, token consumed, wrong token purpose, changed account email | Request a fresh token and confirm the link path is `/verify-email` or `/reset-password` as appropriate. |
| User never receives email in SMTP mode | SMTP host/port/TLS/auth issue, provider rejection, spam filtering | Check app logs for `SMTP delivery failed`, provider logs, sender reputation, SPF/DKIM/DMARC, and TLS settings. |
| User never receives email in console mode | Expected behavior | Switch to `smtp` for real delivery. |
| Link points to localhost or an internal host | Missing or wrong `EMAIL_PUBLIC_BASE_URL` | Set `EMAIL_PUBLIC_BASE_URL` to the public HTTPS origin and restart. |
| Repeated resend attempts do nothing | Request interval throttle | Wait at least `EMAIL_TOKEN_MIN_REQUEST_INTERVAL_SECONDS` for the same user/email/purpose. |
| Password recovery always returns the same neutral message | Enumeration-resistant behavior | Confirm the account has a verified email before testing delivery. |

During an incident, do not lower token security globally until SMTP reachability
and provider status have been checked. If a provider outage blocks recovery,
temporarily route SMTP through a tested backup provider and keep the same public
base URL.

## Fallback

Preferred fallback order:

1. Fix the SMTP provider configuration or route through a tested backup SMTP
   relay.
2. Temporarily switch to `console` only in a private, operator-controlled
   environment where end-user recovery is not required.
3. Switch to `disabled` only when email verification and recovery are
   intentionally unavailable.

Changing email mode does not invalidate existing tokens. If a message may have
been exposed or delivered to the wrong destination, ask the user to request a
new token; issuing a fresh token for the same purpose consumes older active
tokens for that user during successful verification or reset.
