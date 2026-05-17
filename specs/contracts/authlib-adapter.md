# Authlib FastAPI Adapter Contract

Status: draft
Area: OAuth/OIDC
Last Updated: 2026-05-17

## Intent

Describe the local adapter layer that lets Authlib's synchronous OAuth2 server
helpers run behind FastAPI/Starlette request handlers.

## Modules

- `satoidc/satoidc/fastapi_oauth2/requests.py`
- `satoidc/satoidc/fastapi_oauth2/authorization_server.py`
- `satoidc/satoidc/fastapi_oauth2/resource_protector.py`

## Request Adapter

The adapter turns Starlette `Request` objects into Authlib-compatible OAuth2
request payloads.

Current behavior:

- Reads query parameters.
- Reads cached form body when available.
- Reads cached JSON body when content type is JSON.
- Ignores invalid JSON.
- Handles JSON values that are empty strings or lists.
- Leaves body caching to route handlers before entering threadpool work.

## Authorization Server Adapter

The local `AuthorizationServer` wrapper delegates to Authlib while accepting
FastAPI/Starlette requests.

Current route usage:

- Validate consent request for `/authorize`.
- Create authorization response from `POST /oauth/authorize`.
- Create token response from `POST /oauth/token`.
- Create introspection and revocation endpoint responses.

Synchronous Authlib work is run from async routes through
`starlette.concurrency.run_in_threadpool`.

## Resource Protector Adapter

The local `ResourceProtector` wrapper:

- Accepts FastAPI/Starlette request objects.
- Supports direct acquisition through `acquire(...)`.
- Supports decorator usage.
- Translates OAuth errors into FastAPI-compatible responses.
- Provides UserInfo resource protection for `/oauth/userinfo`.

## Session Cleanup

OAuth routes must call `remove_sync_session()` after synchronous Authlib work.

Current wrappers do this in `finally` blocks for:

- authorization response creation.
- token response creation.
- endpoint response creation.
- userinfo acquisition.

## Acceptance Criteria

- Given a Starlette request with query and cached form body, when Authlib reads
  payload data, then both sources are available.
- Given a JSON request body, when Authlib reads payload data, then object values
  are available.
- Given invalid JSON, when the adapter parses the body, then it ignores the
  invalid body instead of raising.
- Given OAuth errors inside resource protection, then they are translated into
  HTTP responses.
- Given OAuth route threadpool work completes, then the sync scoped session is
  removed.
- Given concurrent token endpoint requests run against PostgreSQL, then the
  Authlib threadpool path issues tokens without sharing one process-global
  SQLAlchemy session.
