import asyncio
import base64
import hashlib
import secrets
import socket
import threading
import time
import urllib.parse
from collections.abc import Iterator
from http import HTTPStatus

import httpx
import nicegui.run
import pytest
import pytest_asyncio
import uvicorn
from fastapi import FastAPI, Request
from playwright.async_api import Browser, Page, async_playwright
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import (
    HTMLResponse,
    PlainTextResponse,
    RedirectResponse,
)

from satoidc.main import app
from satoidc.models.database import get_session

PASSWORD = "StrongPass1!"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


@pytest_asyncio.fixture
async def browser() -> Browser:
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        try:
            yield browser
        finally:
            await browser.close()


@pytest.fixture
def live_server(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> Iterator[str]:
    async def override_get_session():
        yield db_session

    app.dependency_overrides[get_session] = override_get_session
    monkeypatch.setattr(nicegui.run, "setup", lambda: None)
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        log_level="warning",
        lifespan="on",
        ws="wsproto",
    )
    server = uvicorn.Server(config)

    def run_server() -> None:
        asyncio.run(server.serve())

    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()

    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            response = httpx.get(
                f"{base_url}/.well-known/openid-configuration",
                timeout=1,
            )
            if response.status_code == HTTPStatus.OK:
                break
        except httpx.HTTPError:
            time.sleep(0.1)
    else:
        server.should_exit = True
        thread.join(timeout=5)
        pytest.fail("Timed out waiting for SatOIDC e2e server")

    try:
        yield base_url
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def page(browser: Browser) -> Page:
    context = await browser.new_context()
    page = await context.new_page()
    try:
        yield page
    finally:
        await context.close()


@pytest.fixture
def oidc_client_app(live_server: str) -> Iterator[dict]:  # noqa: PLR0915
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    redirect_uri = f"{base_url}/callback"
    client_config = {
        "client_id": "browser-client",
        "client_secret": "",
        "scope": "openid email profile",
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
            "scope": client_config.get("scope", "openid email profile"),
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

    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
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
