# OAuth Client Registration Flow

Status: draft
Area: OAuth/UI
Last Updated: 2026-05-13

## Intent

Describe the current OAuth2/OIDC client creation page and developer dashboard
behavior.

## Routes

- `GET /create_client`
- `GET /dashboard/developer`

Both require developer-like access through `page_security`:

- `developer`
- `admin`
- `root` through root bypass.

## Create Client Page

The create client page renders:

- Client name.
- Client URI.
- Allowed scope.
- Redirect URIs.
- Allowed grant types.
- Allowed response types.
- Token endpoint auth method.

Default form values:

- Scope: `openid profile email`
- Grant type: `authorization_code`
- Response type: `code`
- Token endpoint auth method: `client_secret_basic`

## Metadata Validation

Before persistence, `build_client_metadata(...)` validates and normalizes:

- Client name is required.
- Client URI, when present, must be absolute HTTP(S).
- At least one redirect URI is required.
- Every redirect URI must be absolute HTTP(S).
- Grant types must be supported.
- Response types must be supported.
- `code` response type requires `authorization_code` grant.
- At least one scope is required.
- Scopes must be supported.
- Token endpoint auth method must be supported.

Supported grant types:

- `authorization_code`
- `refresh_token`

Supported response types:

- `code`

Supported scopes:

- `openid`
- `profile`
- `email`

Supported token endpoint auth methods:

- `none`
- `client_secret_basic`
- `client_secret_post`

## Persistence

On valid submission:

1. Generates `client_id` with `token_urlsafe(32)`.
2. Stores `client_id_issued_at` as current Unix time.
3. Generates `client_secret` with `token_urlsafe(64)` unless auth method is
   `none`.
4. Stores an `OAuth2Client` owned by the current user.
5. Stores normalized client metadata through Authlib's client mixin.
6. Shows client id and secret once in a dialog.

## Developer Dashboard

The developer dashboard:

- Lists clients owned by the current session user.
- Provides search/filter through `ui.table`.
- Shows count of registered clients.
- Shows an empty state when the user has no clients.
- Shows compact per-client details and redirect URIs.
- Lets the owner edit client metadata using the same validation contract as
  client creation.
- Lets the owner rotate a confidential client secret and shows the new secret
  once.
- Lets the owner disable or re-enable a client registration.
- Lets the owner delete a client registration after confirmation.
- Provides copy affordances for client identifiers and one-time secrets.

Current limitations:

- No post-creation secret reveal beyond initial creation dialog.

## Acceptance Criteria

- Given a user without developer-like access, when they request
  `/create_client`, then access is denied.
- Given valid metadata, when submitted, then an OAuth client is persisted with
  normalized metadata.
- Given invalid metadata, when submitted, then no client is persisted and errors
  are surfaced through notifications.
- Given auth method `none`, when a client is created, then no client secret is
  generated.
- Given a newly created confidential client, then client id and secret are shown
  once after creation.
- Given a developer user with clients, when opening `/dashboard/developer`, then
  the table and details reflect only that user's clients.
- Given a developer edits valid client metadata, when saved, then the stored
  metadata is normalized and updated.
- Given invalid edited metadata, when saved, then no update is persisted and
  validation errors are shown.
- Given a confidential client, when rotating the secret, then the stored secret
  changes and the new value is shown once with copy affordances.
- Given a public client, when rotating the secret, then rotation is rejected.
- Given a disabled client, when OAuth/Authlib queries it, then the provider
  treats it as unavailable.
- Given a client owner deletes a client, when confirmed, then that registration
  is removed from the dashboard.
