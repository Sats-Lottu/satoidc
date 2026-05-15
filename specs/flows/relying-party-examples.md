# Relying-Party Example Flows

Status: draft
Area: Examples/OIDC
Last Updated: 2026-05-15

## Intent

Describe the current example OIDC relying-party clients in `examples/`.

## Confidential Client

File:

- `examples/basic_client.py`

Current behavior:

- Uses Authlib Starlette client integration.
- Expects a registered confidential client id and secret.
- Redirects users to SatOIDC authorization endpoint.
- Exchanges authorization code for tokens.
- Validates key returned user fields such as issuer, audience, and expiration
  expectations.

## Public Client

File:

- `examples/public_client.py`

Current behavior:

- Takes a client id argument.
- Uses `token_endpoint_auth_method=none`.
- Uses PKCE with `code_challenge_method=S256`.
- Starts through Poetry task `start_public_client <client-id>`.

## Expected SatOIDC Client Configuration

For the public example:

- Token endpoint auth method: `none`.
- Response type: `code`.
- Grant type: `authorization_code`.
- Redirect URI must match the example callback URL.
- Scope should include `openid` and any desired profile/email scopes.

For the confidential example:

- Token endpoint auth method should use client secret authentication.
- Client secret must match the registered OAuth client.
- Redirect URI must match the example callback URL.

## Current Gaps

- Examples are not covered by the default unit test suite.
- README/example text may contain encoding issues in some shell sessions.
- Browser e2e coverage now exercises equivalent authorization-code flows with
  in-test relying-party clients for public PKCE and confidential
  `client_secret_post`; it does not launch the standalone example scripts.

## Acceptance Criteria

- Given a registered public client with matching redirect URI, when the public
  example starts, then it can initiate an authorization code + PKCE flow.
- Given a registered confidential client with matching secret and redirect URI,
  when the confidential example starts, then it can initiate an authorization
  code flow and exchange the code.
- Given client metadata does not match redirect URI or auth method, then the
  example flow fails through OAuth validation rather than silently succeeding.
