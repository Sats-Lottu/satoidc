import asyncio
import socket
import threading
import time
from collections.abc import Iterator
from http import HTTPStatus

import httpx
import nicegui.run
import pytest
import uvicorn
from playwright.async_api import Page, expect
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.models import SetupState, User
from setup_wizard.__main__ import create_app
from tests.e2e.conftest import PASSWORD


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture
def setup_live_server(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> Iterator[str]:
    monkeypatch.setattr(nicegui.run, "setup", lambda: None)
    setup_app = create_app()
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    config = uvicorn.Config(
        setup_app,
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
            response = httpx.get(base_url, timeout=1)
            if response.status_code == HTTPStatus.OK:
                break
        except httpx.HTTPError:
            time.sleep(0.1)
    else:
        server.should_exit = True
        thread.join(timeout=5)
        pytest.fail("Timed out waiting for setup wizard e2e server")

    try:
        yield base_url
    finally:
        server.should_exit = True
        thread.join(timeout=10)


async def _assert_no_horizontal_overflow(page: Page) -> None:
    overflow = await page.evaluate(
        """
        () => {
          const root = document.documentElement;
          const body = document.body;
          const width = Math.max(root.clientWidth, window.innerWidth);
          return root.scrollWidth > width + 2 || body.scrollWidth > width + 2;
        }
        """
    )

    assert overflow is False


@pytest.mark.e2e
async def test_setup_wizard_reviews_and_applies_masked_root(
    page: Page,
    setup_live_server: str,
    db_session: AsyncSession,
):
    await page.set_viewport_size({"width": 1280, "height": 900})
    response = await page.goto(
        setup_live_server, wait_until="domcontentloaded"
    )

    assert response is not None
    assert response.status == HTTPStatus.OK
    await expect(
        page.get_by_text("Setup diagnostics", exact=True)
    ).to_be_visible()
    await expect(page.get_by_text("Create Root", exact=True)).to_be_visible()

    await page.get_by_label("Login").fill("RootAdm")
    await page.get_by_label("Email").fill("ROOT@example.com")
    await page.get_by_label("Password", exact=True).fill(PASSWORD)
    await page.get_by_label("Confirm password").fill(PASSWORD)
    await page.get_by_role("button", name="Review setup").click()

    await expect(page.get_by_text("Review setup", exact=True)).to_be_visible()
    await expect(page.get_by_text("rootadm", exact=True)).to_be_visible()
    await expect(
        page.get_by_text("root@example.com", exact=True)
    ).to_be_visible()
    await expect(page.get_by_text("********", exact=True)).to_be_visible()
    await expect(page.get_by_text(PASSWORD, exact=True)).to_have_count(0)

    await _assert_no_horizontal_overflow(page)
    await page.set_viewport_size({"width": 390, "height": 844})
    await expect(page.get_by_text("Review setup", exact=True)).to_be_visible()
    await _assert_no_horizontal_overflow(page)

    await page.get_by_role("button", name="Create root account").click()

    await expect(page.get_by_text("Setup Complete")).to_be_visible()
    setup_state = await db_session.scalar(
        select(SetupState).where(SetupState.state == "completed")
    )
    user = await db_session.scalar(
        select(User).where(User.login == "rootadm")
    )

    assert setup_state is not None
    assert user is not None

    await page.set_viewport_size({"width": 1280, "height": 900})
    reconfiguration_response = await page.goto(
        setup_live_server, wait_until="domcontentloaded"
    )

    assert reconfiguration_response is not None
    assert reconfiguration_response.status == HTTPStatus.OK
    await expect(
        page.get_by_text("Setup Access Required", exact=True)
    ).to_be_visible()

    await page.get_by_label("Login or email").fill("rootadm")
    await page.get_by_label("Password").fill(PASSWORD)
    await page.get_by_role("button", name="Continue").click()

    await expect(page.get_by_text("Service Setup", exact=True)).to_be_visible()
    await expect(
        page.get_by_text("Locked runtime settings", exact=True)
    ).to_be_visible()
    await expect(
        page.get_by_text("OAUTH2_JWT_ISS", exact=True).first
    ).to_be_visible()
    await expect(page.get_by_text("High impact").first).to_be_visible()
    await _assert_no_horizontal_overflow(page)

    await page.get_by_role("button", name="Review high-impact changes").click()
    await expect(
        page.get_by_text("Confirm high-impact changes", exact=True)
    ).to_be_visible()
    await expect(
        page.get_by_text("Verify discovery, JWKS, token, and login behavior.")
    ).to_be_visible()
    await page.get_by_role("button", name="I understand").click()

    await page.set_viewport_size({"width": 390, "height": 844})
    await expect(page.get_by_text("Service Setup", exact=True)).to_be_visible()
    await _assert_no_horizontal_overflow(page)
