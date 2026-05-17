import asyncio
import socket
import threading
import time
from collections.abc import Iterator
from http import HTTPStatus

import httpx
import nicegui.run
import pytest
import pytest_asyncio
import uvicorn
from playwright.async_api import Browser, Page, async_playwright
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.main import app
from satoidc.models.database import get_session


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


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
