# Profile Flow

Status: draft
Area: Auth/UI
Last Updated: 2026-05-13

## Intent

Describe the current authenticated profile page behavior.

## Route

- `GET /profile`
- Implemented by `satoidc/satoidc/routes/profile.py`.
- Protected by `AuthMiddleware`.

## Data Loading

1. Reads `request.session["user_id"]`.
2. Loads the corresponding `User`.
3. Eager-loads active permissions with `selectinload` plus criteria:
   - `disabled == false`
   - `expiration_date > now OR expiration_date IS NULL`
4. Displays wallet state and permission chips.

## Displayed Sections

- Account summary with nickname, email, wallet state, permissions, and logout.
- User Info card.
- Security card.
- Developer Access card.
- Wallet Connection card.
- Quick Actions card.

## Implemented Mutations

Nickname:

- Opens a dialog.
- Validates nickname format.
- Stores `Satoshi` when the submitted value is empty.

Email:

- Opens a dialog.
- Validates email format.
- Rejects duplicate email values from other users.
- Stores lowercased email.

Password:

- Opens a dialog.
- Requires current password when the account already has one.
- Accepts password setup when the account has no password.
- Validates password strength.
- Requires confirmation match.
- Stores a hashed password.

Wallet unlink:

- Opens a dialog.
- Requires a password hash to exist before removing the wallet key.
- Sets `lnurl_pubkey` to null.

## Placeholder Behavior

Still not implemented:

- Wallet link.
- Wallet relink.
- Developer permission request persistence.

The developer request button currently shows a success notification without
creating a request; `specs/features/permission-requests/spec.md` defines the
intended workflow.

## Permission-Based Links

- Users with `developer`, `admin`, or `root` see developer dashboard access.
- Users with `admin` or `root` see admin dashboard access.
- Users with no active permissions see the developer permission request area.

## Acceptance Criteria

- Given a signed-in user, when they open `/profile`, then profile summary,
  active permissions, and wallet state render.
- Given a valid nickname change, when saved, then the user's nickname updates.
- Given an invalid nickname change, when saved, then no update is persisted.
- Given a valid email change to an unused email, when saved, then the email
  updates.
- Given a duplicate email, when saved, then no update is persisted.
- Given a valid password change, when saved, then the stored password hash
  changes and the plain password is not stored.
- Given a wallet-linked user with no password, when unlinking, then the unlink
  is rejected.
- Given a wallet-linked user with a password, when unlinking, then
  `lnurl_pubkey` becomes null.
