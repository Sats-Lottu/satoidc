from http import HTTPStatus

import pytest
from playwright.async_api import Page, expect
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth.security import hash_password
from satoidc.models import OAuth2Client
from tests.e2e.conftest import PASSWORD


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
