# Examples - SatOIDC Clients

This directory contains NiceGUI relying-party examples that integrate with SatOIDC through OAuth2/OIDC.

## Goal

The examples show how to:

- Configure an OIDC client.
- Redirect the browser to `/authorize`.
- Receive an authorization code.
- Exchange the code for tokens at `/oauth/token`.
- Validate the ID Token.
- Consume `/oauth/userinfo`.
- Keep an authenticated NiceGUI client session.

## Flow

```text
NiceGUI App (Client)
        |
        v
   SatOIDC (/authorize)
        |
        v
 Redirect + code
        |
        v
   SatOIDC (/oauth/token)
        |
        v
 ID Token + Access Token
```

## Prerequisites

- Python 3.11+.
- SatOIDC running locally, usually at `http://localhost:8000`.
- A client registered in SatOIDC.

## Running

From the Poetry project root:

```bash
cd satoidc
poetry run python ../examples/basic_client.py
```

For the public PKCE client:

```bash
cd satoidc
poetry run task start_public_client <client-id>
```

Client examples usually listen on:

```text
http://localhost:8001
```

## Configuration

For `basic_client.py`, configure:

```python
CLIENT_ID = "your-client-id"
CLIENT_SECRET = "your-client-secret"
```

The `redirect_uri` registered in SatOIDC must match the URI used by the example.

## Examples

| Example | Focus |
| --- | --- |
| `basic_client.py` | Confidential OIDC client using a client secret. |
| `public_client.py` | Public OIDC client using PKCE. |

## Security

- Use HTTPS in production.
- Do not expose `client_secret` in frontend code.
- Prefer the public client example for browser-only applications.

See the repository [README](../README.md) and [OIDC contract](../specs/contracts/oidc.md) for the provider endpoint contract.
