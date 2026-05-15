# Authorization Code Flow

Status: implemented
Updated: 2026-05-15

## Happy Path

1. Client sends browser to `/authorize` with OAuth/OIDC query parameters.
2. SatOIDC validates the consent request through Authlib.
3. SatOIDC stores CSRF token in the session.
4. User approves consent.
5. Browser submits to `/oauth/authorize`.
6. SatOIDC checks session, CSRF token, and user.
7. Authlib creates the authorization response and stores authorization code.
8. Client exchanges code at `/oauth/token`.
9. Authlib validates code, PKCE, and client authentication.
10. SatOIDC returns tokens.

## Current Constraints

- Authorization Code Grant supports `client_secret_basic`, `client_secret_post`, and `none`.
- PKCE is required for Authorization Code Grant.
- OpenID Code extension requires nonce.
- Code expiry is 300 seconds.

## Risks To Resolve

- Browser e2e tests cover public client PKCE and confidential
  `client_secret_post` flows.
- Discovery metadata and actual grant registrations should stay aligned.
