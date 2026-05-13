# Spec: Permission Requests

## Status

- Status: implemented
- Owner: project maintainers
- Created: 2026-05-13
- Updated: 2026-05-13
- Related code:
  - `satoidc/satoidc/routes/profile.py`
  - `satoidc/satoidc/routes/dashboard.py`
  - `satoidc/satoidc/routes/create_client.py`
  - `satoidc/satoidc/auth/security.py`
  - `satoidc/satoidc/models/__init__.py`
- Related specs:
  - `specs/flows/page-security.md`
  - `specs/flows/home-and-client-console.md`

## Intent

Users without developer access must be able to request permission to create
OIDC clients and use the developer dashboard. Admins must see those requests
as actionable notifications in the admin dashboard, then approve or deny them
with an auditable result.

The feature replaces the current placeholder profile action and static admin
dashboard row with a real permission request workflow.

## Context

SatOIDC currently protects `/dashboard/developer` and `/create_client` with
developer-like permissions. Users without those permissions see profile UI that
offers a "Request developer permissions" action, but the action only shows a
notification and persists nothing. The admin dashboard currently renders a
static permission request row.

The permission taxonomy treats `developer` as a first-class application
permission. `root` remains all-powerful, `admin` includes operational admin
views, and `developer` grants access to developer dashboard and OAuth client
registration.

## Scope

In scope:

- Persisting permission requests from authenticated users.
- Requesting developer access from `/profile`.
- Showing pending requests as admin dashboard notifications.
- Listing, filtering, approving, and denying requests in the admin dashboard.
- Granting developer access on approval.
- Recording approver, decision, reason, and timestamps.
- Preventing duplicate pending requests for the same user and permission.
- Tests for request creation, duplicate handling, approval, denial, and admin
  authorization.

Out of scope:

- Self-service approval.
- Email, Slack, or external notification delivery.
- Fine-grained OAuth client roles beyond developer access.
- Permission categories beyond `root`, `admin`, `developer`, and `support`.
- Client management actions such as editing clients or rotating secrets.

## Permission Request States

Permission requests must have an explicit state:

- `pending`: submitted by a user and awaiting admin decision.
- `approved`: approved by an admin and applied to the user.
- `denied`: denied by an admin with an optional reason.
- `cancelled`: cancelled by the requester before decision.
- `superseded`: replaced by a newer request or made irrelevant by a direct
  permission grant.

Only `pending` requests should appear in the default admin notification count.

## Rules

- Only authenticated users may create permission requests.
- Users who already have `developer`, `admin`, or `root` access must not create
  a duplicate developer access request.
- A user may have at most one `pending` request for the same permission type.
- Admin dashboard request actions require admin-like access. `root` must remain
  all-powerful through the existing authorization rule.
- Approving a request grants the requested permission to the requester.
- Denying a request must not change the requester's existing permissions.
- Approve and deny actions must be idempotent for already-decided requests.
- Requests must store enough audit data to explain who asked, who decided, when
  the decision happened, and why.
- Request reasons and decision notes are user-supplied text and must be treated
  as untrusted display data.
- The UI must not expose unrelated user secrets, password hashes, LNURL private
  material, client secrets, or session data to admins.

## Flows

### Request Developer Access

1. A signed-in user opens `/profile`.
2. The page detects that the user lacks developer/admin/root access.
3. The user selects `Request developer permissions`.
4. The UI asks for an optional short reason.
5. The server creates a `pending` permission request for developer access.
6. The user sees a clear submitted state and cannot create another duplicate
   pending request.
7. Admin users see the request count in the admin dashboard notification area.

### Approve Request

1. An admin opens `/dashboard/admin`.
2. Pending permission requests are shown with requester identity, requested
   permission, reason, age, and current status.
3. The admin selects `Approve`.
4. The server verifies the request is still pending.
5. The server grants the requested permission to the requester.
6. The request state becomes `approved`.
7. The admin dashboard updates the pending count and request list.

### Deny Request

1. An admin opens `/dashboard/admin`.
2. The admin selects `Deny`.
3. The UI optionally collects a denial reason.
4. The server verifies the request is still pending.
5. The request state becomes `denied`.
6. No new permission is granted.
7. The requester can see that the request was denied and may submit a new
   request only if the product policy allows it.

### Cancel Request

1. A user with a pending request opens `/profile`.
2. The user selects `Cancel request`.
3. The server verifies that the requester owns the pending request.
4. The request state becomes `cancelled`.
5. Admin notification counts no longer include the request.

## Contracts

### Persistence

The permission request persistence model includes:

- `id`: primary key.
- `requester_id`: user who requested access.
- `permission_type`: requested permission, initially `developer`.
- `status`: pending, approved, denied, cancelled, or superseded.
- `reason`: optional requester reason.
- `decision_reason`: optional admin reason for approval or denial.
- `decided_by`: admin/root user who decided the request.
- `decided_at`: decision timestamp.
- `created_at`: request timestamp.
- `updated_at`: last update timestamp.

Database constraints:

- Only one active pending request per `requester_id` and `permission_type`.
- Indexed lookup by `status`, `permission_type`, `requester_id`, and
  `created_at`.

### UI

Profile page:

- Show request action only when the user lacks developer-like access.
- Show pending/approved/denied/cancelled status when a request exists.
- Avoid claiming the request was sent unless persistence succeeds.

Admin dashboard:

- Replace static request rows with database-backed data.
- Show notification badge/count for pending requests.
- Include tabs or filters for `Pending`, `Approved`, `Denied`, and `All`.
- Show requester name/login/email, requested permission, reason, age, status,
  and decision metadata.
- Provide approve and deny actions only for pending requests.
- Show empty states for no pending requests and no history.

### Internal Services

Implementation uses service/helper functions instead of route-local database
logic:

- `create_permission_request(...)`
- `list_permission_requests(...)`
- `approve_permission_request(...)`
- `deny_permission_request(...)`
- `cancel_permission_request(...)`
- `get_pending_permission_request_count(...)`

## Admin Dashboard Improvements

The admin dashboard should become an operational review console, not a single
static list.

Useful first version widgets:

- Pending permission requests count.
- Recently approved/denied requests.
- Total users.
- Users with developer access.
- Registered OAuth clients.
- Recently created clients.
- Disabled or expired permissions.
- Quick links to profile, developer dashboard, and setup/diagnostics pages.

Useful table controls:

- Search by requester name, login, email, or permission.
- Filter by status and permission type.
- Sort by created date and decision date.
- Compact row details for reason and decision notes.

Useful empty/error states:

- No pending requests.
- Request already decided by another admin.
- Permission grant failed and request stayed pending.
- Requester no longer exists.

## Acceptance Criteria

- Given a signed-in user without developer access, when they submit a developer
  access request, then a pending permission request is persisted.
- Given a user with an existing pending developer request, when they submit
  again, then no duplicate request is created and the UI reports the existing
  pending state.
- Given a user with developer, admin, or root access, when they open the
  profile, then the developer request action is hidden or disabled.
- Given an admin with pending requests, when they open `/dashboard/admin`, then
  the pending count and request rows reflect database state.
- Given an admin approves a pending request, then the requester receives the
  requested permission and the request becomes approved.
- Given an admin denies a pending request, then no permission is granted and the
  request becomes denied.
- Given a non-admin user calls an approval or denial route/action, then the
  request is rejected.
- Given two admins decide the same request concurrently, then only the first
  decision changes state and the second sees an already-decided result.

## Test Plan

- Unit:
  - request status transitions.
  - duplicate pending request rejection.
  - developer/admin/root access detection.
  - idempotent approval and denial helpers.
- Integration:
  - profile request creation persists data.
  - admin approval grants permission.
  - admin denial does not grant permission.
  - non-admin approval/denial is rejected.
  - pending count matches database state.
- UI/manual:
  - profile shows request, pending, approved, and denied states.
  - admin dashboard shows notification count, filters, empty states, and
    approve/deny actions.
  - desktop and mobile layouts do not overflow.
- Security/regression:
  - requester cannot approve their own request without admin access.
  - request reason and decision notes render as text, not HTML.
  - no secrets appear in admin request lists.
  - root bypass remains valid.

## Implementation Notes

- Add a SQLAlchemy model and Alembic migration for permission requests.
- Consider adding a `developer` permission value to the canonical permission
  enum or document how custom string permissions are supported.
- Route-level UI callbacks should delegate mutation logic to helper functions
  so behavior can be unit tested outside NiceGUI rendering.
- Admin notifications can start as an in-app count/badge in the admin dashboard;
  external delivery can be added later.
- If the app later supports multiple admins, approval/denial should update by
  `id` and `status == pending` to avoid double decisions.

## Traceability

- Code:
  - `satoidc/satoidc/models/__init__.py`
  - `satoidc/satoidc/routes/profile.py`
  - `satoidc/satoidc/routes/dashboard.py`
  - `satoidc/satoidc/auth/security.py`
- Tests:
  - new focused permission request helper tests.
  - integration tests for profile/admin flows.
  - authenticated e2e tests for profile and admin dashboard.
- Docs:
  - `agent-memory/ui-backlog.md`
  - `agent-memory/ui-index.md`
- Decisions:
  - permission taxonomy decision still needed for `developer`.
