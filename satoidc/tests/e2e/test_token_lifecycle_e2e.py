from http import HTTPStatus

import httpx
import pytest
from playwright.async_api import Page, expect
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth.security import hash_password
from satoidc.models import OAuth2Client
from tests.e2e.conftest import PASSWORD


async def _run_browser_auth(
    page: Page,
    oidc_client_app: dict,
    username: str,
    client_name: str,
) -> dict:
    """Helper to run browser login/consent and return resulting token."""
    await page.goto(
        oidc_client_app["base_url"],
        wait_until="domcontentloaded",
    )
    await expect(page.get_by_text("Sign in")).to_be_visible()
    await page.get_by_label("Email or Login").fill(username)
    await page.get_by_label("Password").fill(PASSWORD)
    await page.get_by_role("button", name="Login", exact=True).click()

    await expect(
        page.get_by_text(f"{client_name} wants to access")
    ).to_be_visible()
    await page.get_by_role("button", name="Allow access").click()

    # Wait for the client callback page to render (either success or failure)
    await expect(page.get_by_role("heading", level=1)).to_be_visible()

    result = oidc_client_app["result"]
    assert result["token_status"] == HTTPStatus.OK
    return result["token"]


@pytest.mark.e2e
async def test_token_introspection_and_isolation_e2e(
    page: Page,
    db_session: AsyncSession,
    make_user,
    oidc_client_app: dict,
    live_server: str,
):
    client_id_1 = "client-1"
    client_secret_1 = "secret-1"

    oidc_client_app["client_config"]["client_id"] = client_id_1
    oidc_client_app["client_config"]["client_secret"] = client_secret_1

    user = await make_user(
        login="intro_user",
        email="intro_user@example.com",
        nickname="Intro User",
        password_hash=hash_password(PASSWORD),
    )

    client_1 = OAuth2Client(
        user_id=user.id,
        client_id=client_id_1,
        client_secret=client_secret_1,
        client_id_issued_at=1,
    )
    client_1.set_client_metadata(
        {
            "client_name": "Intro Client 1",
            "client_uri": oidc_client_app["base_url"],
            "scope": "openid email profile",
            "redirect_uris": [oidc_client_app["redirect_uri"]],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post",
        }
    )
    db_session.add(client_1)

    client_id_2 = "client-2"
    client_secret_2 = "secret-2"
    client_2 = OAuth2Client(
        user_id=user.id,
        client_id=client_id_2,
        client_secret=client_secret_2,
        client_id_issued_at=1,
    )
    client_2.set_client_metadata(
        {
            "client_name": "Intro Client 2",
            "client_uri": "http://127.0.0.1:9999",
            "scope": "openid email",
            "redirect_uris": ["http://127.0.0.1:9999/callback"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post",
        }
    )
    db_session.add(client_2)
    await db_session.commit()

    token = await _run_browser_auth(
        page, oidc_client_app, "intro_user", "Intro Client 1"
    )
    access_token = token["access_token"]

    async with httpx.AsyncClient() as client:
        # Introspect with owning client
        resp = await client.post(
            f"{live_server}/oauth/introspect",
            data={"token": access_token},
            auth=(client_id_1, client_secret_1),
        )
        assert resp.status_code == HTTPStatus.OK
        intro_1 = resp.json()
        assert intro_1["active"] is True
        assert intro_1["client_id"] == client_id_1
        assert intro_1["sub"] == str(user.id)
        assert "profile" in intro_1["scope"]

        # Introspect with non-owning client
        resp = await client.post(
            f"{live_server}/oauth/introspect",
            data={"token": access_token},
            auth=(client_id_2, client_secret_2),
        )
        assert resp.status_code == HTTPStatus.OK
        intro_2 = resp.json()
        assert intro_2["active"] is False


@pytest.mark.e2e
async def test_userinfo_scope_protection_e2e(
    page: Page,
    db_session: AsyncSession,
    make_user,
    oidc_client_app: dict,
    live_server: str,
):
    client_id_1 = "clientinfo-1"
    client_secret_1 = "secretinfo-1"

    oidc_client_app["client_config"]["client_id"] = client_id_1
    oidc_client_app["client_config"]["client_secret"] = client_secret_1

    user = await make_user(
        login="info_user",
        email="info_user@example.com",
        nickname="Info User",
        password_hash=hash_password(PASSWORD),
    )

    client_1 = OAuth2Client(
        user_id=user.id,
        client_id=client_id_1,
        client_secret=client_secret_1,
        client_id_issued_at=1,
    )
    client_1.set_client_metadata(
        {
            "client_name": "Info Client 1",
            "client_uri": oidc_client_app["base_url"],
            "scope": "openid email profile",
            "redirect_uris": [oidc_client_app["redirect_uri"]],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post",
        }
    )
    db_session.add(client_1)

    client_id_2 = "clientinfo-no-profile"
    client_secret_2 = "secretinfo-no-profile"
    client_2 = OAuth2Client(
        user_id=user.id,
        client_id=client_id_2,
        client_secret=client_secret_2,
        client_id_issued_at=1,
    )
    client_2.set_client_metadata(
        {
            "client_name": "Info Client 2",
            "client_uri": oidc_client_app["base_url"],
            "scope": "openid email",
            "redirect_uris": [oidc_client_app["redirect_uri"]],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post",
        }
    )
    db_session.add(client_2)
    await db_session.commit()

    # 1. Flow with profile scope
    token_1 = await _run_browser_auth(
        page, oidc_client_app, "info_user", "Info Client 1"
    )
    access_token_1 = token_1["access_token"]

    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{live_server}/oauth/userinfo",
            headers={"Authorization": f"Bearer {access_token_1}"},
        )
        assert resp.status_code == HTTPStatus.OK
        userinfo = resp.json()
        assert userinfo["sub"] == str(user.id)
        assert userinfo["email"] == "info_user@example.com"
        assert userinfo["name"] == "Info User"
        assert "lnurl_pubkey" in userinfo

    # 2. Flow without profile scope
    oidc_client_app["client_config"]["client_id"] = client_id_2
    oidc_client_app["client_config"]["client_secret"] = client_secret_2
    oidc_client_app["client_config"]["scope"] = "openid email"

    context = page.context
    await context.clear_cookies()

    token_2 = await _run_browser_auth(
        page, oidc_client_app, "info_user", "Info Client 2"
    )
    access_token_2 = token_2["access_token"]

    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{live_server}/oauth/userinfo",
            headers={"Authorization": f"Bearer {access_token_2}"},
        )
        expected_statuses = {HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN}
        assert resp.status_code in expected_statuses


@pytest.mark.e2e
async def test_token_refresh_and_revocation_e2e(
    page: Page,
    db_session: AsyncSession,
    make_user,
    oidc_client_app: dict,
    live_server: str,
):
    client_id = "client-refresh"
    client_secret = "secret-refresh"

    oidc_client_app["client_config"]["client_id"] = client_id
    oidc_client_app["client_config"]["client_secret"] = client_secret

    user = await make_user(
        login="refresh_user",
        email="refresh_user@example.com",
        nickname="Refresh User",
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
            "client_name": "Refresh Client",
            "client_uri": oidc_client_app["base_url"],
            "scope": "openid email profile",
            "redirect_uris": [oidc_client_app["redirect_uri"]],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post",
        }
    )
    db_session.add(client)
    await db_session.commit()

    token = await _run_browser_auth(
        page, oidc_client_app, "refresh_user", "Refresh Client"
    )
    access_token = token["access_token"]
    refresh_token = token["refresh_token"]

    async with httpx.AsyncClient() as client_http:
        # Refresh Token Rotation
        resp = await client_http.post(
            f"{live_server}/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client_id,
                "client_secret": client_secret,
            },
        )
        assert resp.status_code == HTTPStatus.OK
        refresh_res = resp.json()
        new_access = refresh_res["access_token"]
        new_refresh = refresh_res["refresh_token"]

        assert new_access != access_token
        assert new_refresh != refresh_token

        # Verify new access token is active
        resp = await client_http.post(
            f"{live_server}/oauth/introspect",
            data={"token": new_access},
            auth=(client_id, client_secret),
        )
        assert resp.status_code == HTTPStatus.OK
        assert resp.json()["active"] is True

        # Old Refresh Token Rejection
        resp = await client_http.post(
            f"{live_server}/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client_id,
                "client_secret": client_secret,
            },
        )
        assert resp.status_code == HTTPStatus.BAD_REQUEST
        assert resp.json()["error"] == "invalid_grant"

        # Revocation
        resp = await client_http.post(
            f"{live_server}/oauth/revoke",
            data={
                "token": new_access,
                "token_type_hint": "access_token",
            },
            auth=(client_id, client_secret),
        )
        assert resp.status_code == HTTPStatus.OK

        # Verification after revocation
        resp = await client_http.post(
            f"{live_server}/oauth/introspect",
            data={"token": new_access},
            auth=(client_id, client_secret),
        )
        assert resp.status_code == HTTPStatus.OK
        assert resp.json()["active"] is False

        resp = await client_http.get(
            f"{live_server}/oauth/userinfo",
            headers={"Authorization": f"Bearer {new_access}"},
        )
        expected_statuses = {HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN}
        assert resp.status_code in expected_statuses
