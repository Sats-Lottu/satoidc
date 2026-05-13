# Permission Requests Test Plan

## Unit Tests

- `create_permission_request` creates a pending developer request for a user
  without developer-like access.
- `create_permission_request` rejects duplicate pending requests.
- `create_permission_request` rejects users who already have developer, admin,
  or root access.
- `approve_permission_request` transitions pending to approved.
- `approve_permission_request` grants the requested permission.
- `approve_permission_request` is idempotent for already-approved requests.
- `deny_permission_request` transitions pending to denied.
- `deny_permission_request` stores the decision reason.
- `deny_permission_request` does not grant permissions.
- `cancel_permission_request` only allows the requester to cancel pending
  requests.
- Pending count excludes approved, denied, cancelled, and superseded requests.

## Integration Tests

- Profile developer request action persists a pending request.
- Profile shows pending state after request creation.
- Admin dashboard lists pending requests from the database.
- Admin approval grants access to `/dashboard/developer` and `/create_client`.
- Admin denial keeps `/dashboard/developer` and `/create_client` forbidden for
  the requester.
- Non-admin users cannot approve or deny requests.
- Two approval attempts for the same request leave one final decision.

## UI And E2E Tests

- Authenticated non-developer profile shows request action.
- Authenticated user with pending request sees pending state instead of the
  request button.
- Admin dashboard shows pending request notification count.
- Admin dashboard empty state renders when no pending requests exist.
- Approve action removes the request from the pending table.
- Deny action removes the request from the pending table and records the note.
- Mobile admin dashboard has no horizontal overflow.

## Security Regression Tests

- Request notes render as text when they contain HTML-like content.
- Decision notes render as text when they contain HTML-like content.
- Admin request lists do not include `password_hash`, `client_secret`, OAuth
  tokens, session ids, or LNURL private material.
- Requester cannot view another user's permission request details.
- Root permission bypass still authorizes admin dashboard access.
