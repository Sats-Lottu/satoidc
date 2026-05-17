# Architecture

Updated: 2026-05-08

## System Context

SatOIDC acts as an OpenID Provider. Relying-party clients redirect users to SatOIDC, SatOIDC authenticates users through password or LNURL-auth, then Authlib issues OAuth2/OIDC artifacts.

```mermaid
flowchart LR
    Client["OIDC Client / Relying Party"]
    Browser["User Browser"]
    App["SatOIDC FastAPI + NiceGUI"]
    Authlib["Authlib OAuth2/OIDC Engine"]
    DB["Database"]
    Wallet["Lightning Wallet"]

    Client --> Browser
    Browser --> App
    App --> Authlib
    Authlib --> DB
    App --> DB
    Browser --> Wallet
    Wallet --> App
```

## Main Components

### FastAPI Application

Created in `satoidc/satoidc/main.py`.

Responsibilities:

- Compose middleware.
- Configure Authlib.
- Register routes.
- Attach NiceGUI UI to FastAPI.

### NiceGUI UI

Routes in `satoidc/satoidc/routes/` define pages directly with NiceGUI.

Primary pages:

- Home.
- Register.
- Login.
- Profile.
- OIDC consent.
- OAuth client creation.
- Admin/developer dashboards.

### Authlib Integration

SatOIDC uses Authlib's SQLAlchemy OAuth2 mixins and custom grant classes.

Local adapter files in `satoidc/satoidc/fastapi_oauth2/` bridge Starlette `Request` objects into Authlib's synchronous request abstractions.

### Persistence

The project uses:

- Async SQLAlchemy sessions for FastAPI route dependencies.
- A sync SQLAlchemy session for Authlib helper functions.

Both must point to the same database through `DATABASE_URL` and `SYNC_DATABASE_URL`.

### Schemas

Request and form schemas live in `satoidc/satoidc/schemas/`.

Current schema modules:

- `lnurl.py`: LNURL callback query schema.
- `login.py`: password login form schema.
- `register.py`: password registration form schema.

The old `auth/lnurl_schemas.py` path remains as a compatibility re-export.

### LNURL-auth

LNURL-auth is implemented with challenge records, bech32 LNURL generation, secp256k1 signature verification, and NiceGUI event callbacks.

## Request Flow: Authorization Code

```mermaid
sequenceDiagram
    participant C as Client
    participant B as Browser
    participant S as SatOIDC
    participant A as Authlib
    participant D as Database

    C->>B: Redirect to /authorize
    B->>S: GET /authorize
    S->>A: validate_consent_request
    S->>B: Consent page
    B->>S: POST /oauth/authorize
    S->>A: create_authorization_response
    A->>D: Store authorization code
    S->>B: Redirect with code
    C->>S: POST /oauth/token
    S->>A: create_token_response
    A->>D: Validate code and store token
    S->>C: Tokens
```

## Request Flow: LNURL Login

```mermaid
sequenceDiagram
    participant B as Browser
    participant S as SatOIDC
    participant D as Database
    participant W as Lightning Wallet

    B->>S: GET /login
    S->>D: Create LnurlAuthChallenge
    S->>B: Render QR/lightning LNURL
    B->>W: Scan/open LNURL
    W->>S: GET /auth/lnurl/callback?k1&sig&key&action=login
    S->>D: Validate and mark challenge
    S->>S: Emit lnurl_auth_events
    S->>B: Navigate to redirect endpoint
    B->>S: GET /auth/lnurl/redirect
    S->>B: Set session user_id and redirect
```

## Request Flow: Password Registration

```mermaid
sequenceDiagram
    participant B as Browser
    participant S as SatOIDC
    participant D as Database

    B->>S: GET /register
    S->>B: Render NiceGUI form
    B->>S: POST /register
    S->>S: Validate terms, fields, password confirmation, redirect
    S->>D: Check duplicate login/email
    S->>D: Store User with hashed password
    S->>B: Set session user_id and redirect
```

## Security Boundaries

- Middleware protects non-public paths by checking `request.session["user_id"]`.
- `page_security` adds permission checks for selected NiceGUI pages. It validates session UUID shape, loads active non-disabled permissions, ignores expired permissions, treats `root` as all-powerful, and redirects unauthorized users to `/forbidden`.
- OAuth consent POST validates session and CSRF token.
- Password registration sanitizes `redirect_to` before redirecting.
- LNURL callback validates challenge freshness, action, replay flag, and signature.
- Production deployment must configure strong secrets, persistent signing keys, HTTPS, secure cookies, and database-backed runtime state.
