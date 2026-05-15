# Profile Flow

Status: implemented
Area: Auth/UI
Last Updated: 2026-05-15

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
- Account Information card.
- Security card.
- Wallet Connection card.
- Account Details card with subject ID, login, sign-in method state,
  developer access state, and creation timestamp.
- Developer Access card.

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

Wallet link and relink:

- Opens a dialog with a fresh LNURL-auth QR challenge using `action=link`.
- Stores the current signed-in user on the challenge before rendering the QR.
- Lets the wallet callback attach the wallet public key to that user.
- Rejects a wallet public key that is already linked to another user.
- Refreshes the profile after a successful callback event.
- Relink uses the same link challenge behavior and replaces the account's
  LNURL public key after a successful callback.

## Developer Permission Requests

Users without active elevated permissions can request developer access from the
profile page.

Current behavior:

- Creates a `PermissionRequest` for `developer` access.
- Shows pending and denied states on the profile page.
- Prevents duplicate pending requests.
- Lets root/admin users approve or deny the request from the admin dashboard.
- Grants the `developer` permission when the request is approved.

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
- Given a signed-in user with no wallet, when scanning a valid wallet link QR,
  then `lnurl_pubkey` is set to the wallet linking key.
- Given a signed-in user with an existing wallet, when scanning a valid wallet
  relink QR with a new wallet, then `lnurl_pubkey` is replaced.
- Given a signed-in user scans a wallet key already linked to another account,
  then the callback is rejected and no account is changed.
- Given a signed-in user without elevated permissions requests developer
  access, then a pending permission request is persisted.
- Given a signed-in user already has a pending developer request, when they
  open `/profile`, then the pending state is shown instead of creating another
  request.
