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
poetry run python ../examples/basic_client.py \
  --client-id <client-id> \
  --client-secret <client-secret>
```

For the public PKCE client:

```bash
cd satoidc
poetry run task start_public_client <client-id>
```

Equivalent direct command:

```bash
cd satoidc
poetry run python ../examples/public_client.py --client-id <client-id>
```

Client examples usually listen on:

```text
http://localhost:8001
```

Register this redirect URI for the example client:

```text
http://localhost:8001/auth/callback
```

## Configuration

Both examples accept command-line options and environment variables:

| Option | Environment variable | Default |
| --- | --- | --- |
| `--client-id` | `SATOIDC_CLIENT_ID` | Required |
| `--provider-url` | `SATOIDC_PROVIDER_URL` | `http://localhost:8000` |
| `--scope` | `SATOIDC_SCOPE` | `openid email profile` |
| `--host` | `SATOIDC_CLIENT_HOST` | `localhost` |
| `--port` | `SATOIDC_CLIENT_PORT` | `8001` |
| `--storage-secret` | `SATOIDC_EXAMPLE_STORAGE_SECRET` | Development placeholder |

`basic_client.py` also requires:

| Option | Environment variable | Default |
| --- | --- | --- |
| `--client-secret` | `SATOIDC_CLIENT_SECRET` | Required |

Example using environment variables:

```bash
cd satoidc
SATOIDC_CLIENT_ID=<client-id> \
SATOIDC_CLIENT_SECRET=<client-secret> \
poetry run python ../examples/basic_client.py
```

Use a strong `SATOIDC_EXAMPLE_STORAGE_SECRET` whenever the example is exposed
outside local development.

## Examples

| Example | Focus |
| --- | --- |
| `basic_client.py` | Confidential OIDC client using a client secret. |
| `public_client.py` | Public OIDC client using PKCE. |

Both examples:

- Discover provider metadata from `/.well-known/openid-configuration`.
- Use `/auth/callback` as the redirect path.
- Store validated ID Token claims in NiceGUI per-user storage.
- Validate `exp`, `aud`, and `iss` before reusing the local session.
- Show a small authenticated session page with the returned subject, issuer and
  email when available.
- Render callback errors in the browser and log details server-side.

## Security

- Use HTTPS in production.
- Do not expose `client_secret` in frontend code.
- Prefer the public client example for browser-only applications.

See the repository [README](../README.md) and [OIDC contract](../specs/contracts/oidc.md) for the provider endpoint contract.
