---
title: Architecture Memory
tags:
  - agent-memory/state
type: state
project: satoidc
status: active
updated: 2026-05-06
---

# Architecture Memory

SatOIDC is a FastAPI + NiceGUI OpenID Provider with Authlib as the OAuth2/OIDC engine. The app starts in `satoidc/satoidc/__init__.py`, configures middleware, calls `config_oauth(app)`, includes routers, and attaches NiceGUI through `ui.run_with`.

Core modules:

- `auth/oauth2.py`: Authlib grants, JWT config, generated RSA JWK, userinfo generation, token/introspection/revocation integration.
- `fastapi_oauth2/`: local Starlette/FastAPI request adapter for Authlib.
- `auth/lnurl.py` and `routes/lnurl_auth.py`: LNURL encoding, signature verification, challenge callback, and NiceGUI event integration.
- `models/__init__.py`: User, Permission, LnurlAuthChallenge, OAuth2Client, OAuth2AuthorizationCode, OAuth2Token.
- `routes/`: UI and API routes.
- `setup_wizard/`: first root user bootstrap.

Database uses async sessions for route dependencies and a separate sync session for Authlib SQLAlchemy helpers. Both URLs must point to the same database.
