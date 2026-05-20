import asyncio
import base64
import hashlib
import secrets
import socket
import threading
import urllib.parse
from collections.abc import Iterator
from http import HTTPStatus
from time import monotonic

import httpx
import pytest
import uvicorn
from fastapi import FastAPI, Request
from playwright.async_api import Page, expect
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import (
    HTMLResponse,
    PlainTextResponse,
    RedirectResponse,
)

from satoidc.auth.security import hash_password
from satoidc.models import OAuth2Client

PASSWORD = "StrongPass1!"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


@pytest.fixture
def oidc_client_app(live_server: str) -> Iterator[dict]:  # noqa: PLR0915
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    redirect_uri = f"{base_url}/callback"
    client_config = {
        "client_id": "browser-client",
        "client_secret": "",
    }
    state_store: dict[str, dict[str, str]] = {}
    result: dict[str, object] = {}

    client_app = FastAPI()

    @client_app.get("/health")
    async def health():
        return PlainTextResponse("ok")

    @client_app.get("/")
    async def start_flow():
        state = secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(24)
        verifier = secrets.token_urlsafe(64)
        state_store[state] = {"nonce": nonce, "verifier": verifier}
        params = {
            "response_type": "code",
            "client_id": client_config["client_id"],
            "redirect_uri": redirect_uri,
            "scope": "openid email profile",
            "state": state,
            "nonce": nonce,
            "code_challenge": _pkce_challenge(verifier),
            "code_challenge_method": "S256",
        }
        return RedirectResponse(
            f"{live_server}/authorize?{urllib.parse.urlencode(params)}"
        )

    @client_app.get("/callback")
    async def callback(request: Request):
        state = request.query_params.get("state")
        code = request.query_params.get("code")
        stored = state_store.pop(state or "", None)
        if not stored or not code:
            return HTMLResponse("<h1>Authorization failed</h1>", 400)

        async with httpx.AsyncClient(timeout=10) as client:
            token_response = await client.post(
                f"{live_server}/oauth/token",
                data={
                    "grant_type": "authorization_code",
                    "client_id": client_config["client_id"],
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "code_verifier": stored["verifier"],
                    **(
                        {"client_secret": client_config["client_secret"]}
                        if client_config["client_secret"]
                        else {}
                    ),
                },
            )
            result["token_status"] = token_response.status_code
            result["token"] = token_response.json()
            token_response.raise_for_status()
            token = token_response.json()
            userinfo_response = await client.get(
                f"{live_server}/oauth/userinfo",
                headers={
                    "Authorization": f"Bearer {token['access_token']}"
                },
            )
            result["userinfo_status"] = userinfo_response.status_code
            result["userinfo"] = userinfo_response.json()
            if userinfo_response.status_code != HTTPStatus.OK:
                return HTMLResponse(
                    "<h1>UserInfo failed</h1>"
                    f"<p id='token-scope'>{token.get('scope')}</p>"
                    f"<pre>{userinfo_response.text}</pre>",
                    status_code=userinfo_response.status_code,
                )

        userinfo = result["userinfo"]
        token = result["token"]
        return HTMLResponse(
            "<h1>OIDC flow complete</h1>"
            f"<p id='subject'>{userinfo['sub']}</p>"
            f"<p id='email'>{userinfo['email']}</p>"
            f"<p id='name'>{userinfo['name']}</p>"
            f"<p id='id-token'>{bool(token.get('id_token'))}</p>"
        )

    config = uvicorn.Config(
        client_app,
        host="127.0.0.1",
        port=port,
        log_level="warning",
        lifespan="on",
        ws="none",
    )
    server = uvicorn.Server(config)

    def run_server() -> None:
        asyncio.run(server.serve())

    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()

    deadline = monotonic() + 15
    while monotonic() < deadline:
        try:
            response = httpx.get(f"{base_url}/health", timeout=1)
            if response.status_code == HTTPStatus.OK:
                break
        except httpx.HTTPError:
            pass
    else:
        server.should_exit = True
        thread.join(timeout=5)
        pytest.fail("Timed out waiting for OIDC test client")

    try:
        yield {
            "base_url": base_url,
            "client_id": client_config["client_id"],
            "client_config": client_config,
            "redirect_uri": redirect_uri,
            "result": result,
        }
    finally:
        server.should_exit = True
        thread.join(timeout=10)


@pytest.mark.e2e
@pytest.mark.parametrize(
    ("token_endpoint_auth_method", "client_secret"),
    [
        pytest.param("none", "", id="public-pkce"),
        pytest.param(
            "client_secret_post",
            "confidential-secret",
            id="confidential-post",
        ),
    ],
)
async def test_authorization_code_browser_flow(  # noqa: PLR0913, PLR0917
    page: Page,
    db_session: AsyncSession,
    make_user,
    oidc_client_app: dict,
    token_endpoint_auth_method: str,
    client_secret: str,
):
    client_id = f"{token_endpoint_auth_method}-browser-client"
    oidc_client_app["client_config"]["client_id"] = client_id
    oidc_client_app["client_config"]["client_secret"] = client_secret
    user = await make_user(
        login="oidc_user",
        email="oidc_user@example.com",
        nickname="OIDC User",
        password_hash=hash_password(PASSWORD),
    )
    client = OAuth2Client(
        user_id=user.id,
        client_id=client_id,
        client_secret=client_secret,
        client_id_issued_at=1,
    )
    client.set_client_metadata(
        {
            "client_name": "Public Browser E2E Client",
            "client_uri": oidc_client_app["base_url"],
            "scope": "openid email profile",
            "redirect_uris": [oidc_client_app["redirect_uri"]],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": token_endpoint_auth_method,
        }
    )
    db_session.add(client)
    await db_session.commit()

    await page.goto(oidc_client_app["base_url"], wait_until="domcontentloaded")
    await expect(page.get_by_text("Sign in")).to_be_visible()
    await page.get_by_label("Email or Login").fill("oidc_user")
    await page.get_by_label("Password").fill(PASSWORD)
    await page.get_by_role("button", name="Login", exact=True).click()
    await expect(
        page.get_by_text("Public Browser E2E Client wants to access")
    ).to_be_visible()
    await page.get_by_role("button", name="Allow access").click()

    await expect(page.get_by_text("OIDC flow complete")).to_be_visible()
    await expect(page.locator("#email")).to_have_text(
        "oidc_user@example.com"
    )
    await expect(page.locator("#name")).to_have_text("OIDC User")
    await expect(page.locator("#id-token")).to_have_text("True")

    result = oidc_client_app["result"]
    assert result["token_status"] == HTTPStatus.OK
    assert result["userinfo_status"] == HTTPStatus.OK
    token = result["token"]
    assert token["token_type"] == "Bearer"
    assert "access_token" in token
    assert "id_token" in token
    assert "refresh_token" in token
    assert result["userinfo"]["sub"] == str(user.id)
