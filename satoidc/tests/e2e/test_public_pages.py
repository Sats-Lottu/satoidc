import re

import pytest
from playwright.async_api import Page, expect
from starlette import status

VIEWPORTS = [
    pytest.param({"width": 1280, "height": 900}, id="desktop"),
    pytest.param({"width": 390, "height": 844}, id="mobile"),
]

PUBLIC_PAGES = [
    pytest.param("/", "Welcome to SatOIDC", id="home"),
    pytest.param("/login", "Sign in", id="login"),
    pytest.param("/register", "Create account", id="register"),
    pytest.param("/forbidden", "Forbidden", id="forbidden"),
]


async def _assert_no_console_errors(page: Page) -> None:
    errors: list[str] = []
    page.on(
        "console",
        lambda msg: errors.append(msg.text) if msg.type == "error" else None,
    )
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    await page.wait_for_timeout(300)
    assert errors == []


async def _assert_no_horizontal_overflow(page: Page) -> None:
    overflow = await page.evaluate(
        """
        () => {
          const root = document.documentElement;
          const body = document.body;
          const width = Math.max(root.clientWidth, window.innerWidth);
          const overflowing = [...document.body.querySelectorAll('*')]
            .filter((el) => {
              const rect = el.getBoundingClientRect();
              return rect.width > 0 && rect.right > width + 2;
            })
            .slice(0, 5)
            .map((el) => ({
              tag: el.tagName,
              text: (el.innerText || el.getAttribute('aria-label') || '')
                .slice(0, 80),
              right: Math.round(el.getBoundingClientRect().right),
              width: Math.round(el.getBoundingClientRect().width),
            }));
          return {
            documentOverflow: root.scrollWidth > width + 2 ||
              body.scrollWidth > width + 2,
            overflowing,
          };
        }
        """
    )

    assert overflow["documentOverflow"] is False
    assert overflow["overflowing"] == []


async def _assert_design_baseline(page: Page) -> None:
    controls = await page.locator("button, a, input").count()
    assert controls > 0

    tiny_controls = await page.locator(
        "button:visible, input:visible"
    ).evaluate_all(
        """
        elements => elements
          .filter((el) => {
            const rect = el.getBoundingClientRect();
            return rect.width > 0 && rect.height > 0 && rect.height < 32;
          })
          .map((el) => ({
            tag: el.tagName,
            text: (el.innerText || el.getAttribute('aria-label') || '')
              .slice(0, 60),
            height: Math.round(el.getBoundingClientRect().height),
          }))
        """
    )
    assert tiny_controls == []


@pytest.mark.e2e
def test_oidc_public_metadata_and_jwks_are_canonical(live_server: str):
    metadata = f"{live_server}/.well-known/openid-configuration"
    response = pytest.importorskip("httpx").get(metadata)

    assert response.status_code == status.HTTP_200_OK
    body = response.json()
    assert body["jwks_uri"].endswith("/.well-known/jwks.json")
    assert body["response_types_supported"] == ["code"]
    assert "refresh_token" in body["grant_types_supported"]

    jwks = pytest.importorskip("httpx").get(
        f"{live_server}/.well-known/jwks.json"
    )
    assert jwks.status_code == status.HTTP_200_OK
    key = jwks.json()["keys"][0]
    assert "kid" in key
    assert "d" not in key

    assert pytest.importorskip("httpx").get(
        f"{live_server}/oauth/jwks.json"
    ).status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.e2e
@pytest.mark.parametrize("viewport", VIEWPORTS)
@pytest.mark.parametrize(("path", "text"), PUBLIC_PAGES)
async def test_public_pages_render_responsively(
    page: Page,
    live_server: str,
    viewport: dict[str, int],
    path: str,
    text: str,
):
    await page.set_viewport_size(viewport)
    response = await page.goto(
        f"{live_server}{path}", wait_until="domcontentloaded"
    )

    assert response is not None
    assert response.status == status.HTTP_200_OK
    await expect(page.get_by_text(text, exact=False).first).to_be_visible()
    await _assert_no_console_errors(page)
    await _assert_no_horizontal_overflow(page)
    await _assert_design_baseline(page)


@pytest.mark.e2e
async def test_protected_profile_redirects_to_login_on_mobile(
    page: Page, live_server: str
):
    await page.set_viewport_size({"width": 390, "height": 844})
    await page.goto(f"{live_server}/profile", wait_until="domcontentloaded")

    await expect(page).to_have_url(re.compile(r".*/login.*"))
    await expect(
        page.get_by_text("Sign in", exact=False).first
    ).to_be_visible()
    await _assert_no_horizontal_overflow(page)
