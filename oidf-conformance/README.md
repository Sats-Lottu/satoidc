# OIDF Conformance Suite Local Runner

This directory runs the official OpenID Foundation Conformance Suite locally in
Docker for SatOIDC conformance checks.

The default path uses the OIDF prebuilt images from the GitLab Container
Registry. That is faster and less fragile than building the Java suite locally.
Use the source-build path only when you need to test an exact upstream checkout
or patch the suite itself.

## Sources

- OIDF overview: https://openid.net/certification/about-conformance-suite/
- Hosted suite: https://www.certification.openid.net/
- Source repository: https://gitlab.com/openid/conformance-suite
- Local run documentation:
  https://gitlab.com/openid/conformance-suite/-/wikis/Developers/Build-&-Run

The OIDF suite is open source and free to run for testing. Formal OpenID
certification submission is a separate paid process.

## Prerequisites

- Docker with the Compose plugin.
- `localhost.emobix.co.uk` mapped to `127.0.0.1` on the host.
- A SatOIDC conformance instance reachable by the suite.

On Windows, edit `C:\Windows\System32\drivers\etc\hosts` as Administrator and
add:

```text
127.0.0.1 localhost.emobix.co.uk
```

On Linux/macOS, add the same entry to `/etc/hosts`.

## Start The Suite

From the repository root:

```bash
cd oidf-conformance
docker compose up
```

Open:

```text
https://localhost.emobix.co.uk:8443/
```

The local nginx container uses the suite's self-signed certificate, so the
browser may show a certificate warning.

To stop the suite:

```bash
cd oidf-conformance
docker compose down
```

To reset all local conformance-suite state:

```bash
cd oidf-conformance
docker compose down -v
```

## Pin A Suite Version

For reproducible evidence, copy `.env.example` to `.env` and set `IMAGE_TAG` to
an OIDF release tag from the GitLab container registry or release page.

```bash
cd oidf-conformance
cp .env.example .env
```

Example:

```env
IMAGE_TAG=release-v5.1.43
```

## Connect The Suite To SatOIDC

The suite container must call SatOIDC through a URL that is reachable from inside
Docker and that matches SatOIDC discovery metadata.

For a quick local run, start SatOIDC with:

```env
OAUTH2_JWT_ISS=http://host.docker.internal:8000
EMAIL_PUBLIC_BASE_URL=http://host.docker.internal:8000
SESSION_COOKIE_HTTPS_ONLY=false
```

Then use this discovery URL in the OIDF test plan JSON:

```json
{
  "server": {
    "discoveryUrl": "http://host.docker.internal:8000/.well-known/openid-configuration"
  },
  "client": {
    "client_id": "<client-id>",
    "client_secret": "<client-secret>"
  }
}
```

Some OIDF plans require HTTPS issuer URLs. For those, expose SatOIDC through a
short-lived tunnel or a local HTTPS reverse proxy and set `OAUTH2_JWT_ISS` to
that public HTTPS origin before registering the conformance client.

## Register The SatOIDC Test Client

Start with:

- Profile: `OpenID Connect Core: Basic OP`
- Flow: Authorization Code
- Client type: confidential
- ID Token signing: `RS256`
- Scopes: `openid profile email`

Register a SatOIDC client with a redirect URI that matches the suite alias:

```text
https://localhost.emobix.co.uk:8443/test/a/<ALIAS>/callback
```

For the hosted suite, use:

```text
https://www.certification.openid.net/test/a/<ALIAS>/callback
```

Use `client_secret_post` or `client_secret_basic` for the first confidential
client run. Add PKCE and public-client variants only after Basic OP succeeds.

## Expected SatOIDC Endpoints

SatOIDC currently exposes OIDC endpoints with `/oauth` and `/.well-known`
paths. Verify discovery instead of hard-coding generic endpoint paths:

```text
/.well-known/openid-configuration
/authorize
/oauth/token
/oauth/userinfo
/.well-known/jwks.json
```

The discovery document must advertise the same issuer host that the suite uses.

## Optional Source Build

Use this only when prebuilt images are not enough:

```bash
git clone https://gitlab.com/openid/conformance-suite.git
cd conformance-suite
MAVEN_CACHE=./m2 docker compose -f builder-compose.yml run builder
docker compose up
```

The source-build path belongs outside this repository checkout unless you are
intentionally developing the upstream suite.

## Evidence

Record real runs under:

```text
docs/conformance-results/YYYY-MM-DD-basic-op.md
```

Include the SatOIDC commit SHA, OIDF suite tag, test profile, configuration
summary, pass/fail status, and known deviations.
