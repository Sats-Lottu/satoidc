# LNURL-auth Flow

Status: draft
Updated: 2026-05-06

## Actors

- User browser.
- SatOIDC app.
- Lightning wallet.
- Database.

## Challenge Creation

Login, register, and setup wizard pages create `LnurlAuthChallenge` records and render a bech32 `lnurl` containing:

- `tag=login`
- `k1=<challenge>`
- `action=<register|login|link|auth>`

## Callback

Wallet calls:

```text
GET /auth/lnurl/callback?k1=<hex>&sig=<hex>&key=<hex>&action=<action>
```

Current validation:

1. Find a matching unconsumed challenge.
2. Require challenge timestamp within `LNURL_K1_TTL_SECONDS`.
3. Mark challenge as consumed.
4. Require callback action to equal stored challenge action.
5. Verify secp256k1 signature over `k1`.
6. Execute action-specific behavior.
7. Emit `lnurl_auth_events`.

## Action Behavior

- `register`: create user for `key` when missing, attach challenge to user.
- `login`: require existing user for `key`, attach challenge to user.
- `link`: attach `key` to the challenge user.
- `auth`: currently returns success without extra action binding.

## Risks To Resolve

- Callback attempts intentionally consume the challenge before signature verification as a replay-defense measure, even when the signature is invalid.
- `register` can create a user without email, login, password, and possibly without nickname.
- `auth` action needs a documented meaning before production use.
