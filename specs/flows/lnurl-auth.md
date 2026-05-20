# LNURL-auth Flow

Status: draft
Updated: 2026-05-18

## Actors

- User browser.
- SatOIDC app.
- Lightning wallet.
- Database.

## Challenge Creation

Login, register, and setup wizard pages create `LnurlAuthChallenge` records and render a bech32 `lnurl` containing:

- `tag=login`
- `k1=<challenge>`
- `action=<register|login|link>`

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
## Risks To Resolve

- Callback attempts intentionally consume the challenge before signature verification as a replay-defense measure, even when the signature is invalid.
- `register` can create a user without email, login, or password, but must use
  `satoshi` as the default nickname when no nickname is supplied.

## Decisions

- **Remove `auth` action**: The stateless `auth` action was removed to eliminate uncontracted stateless authentication behavior before production, reducing the attack surface.

## Product Hardening Requirement

LNURL `register` must satisfy the database contract for `User.nickname`.

- New LNURL-only users must receive `satoshi` as the default display nickname.
- The fallback nickname must not expose a full wallet public key.
- A regression test must cover successful LNURL registration against the
  non-null nickname constraint.

See `specs/features/lnurl-registration-valid-user/spec.md`.
