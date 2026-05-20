import asyncio
from http import HTTPStatus
import time
import httpx
import pytest
from playwright.async_api import Page, expect
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth.security import hash_password
from satoidc.models import OAuth2Client, OAuth2Token
from tests.e2e.test_oauth_authorization_code_e2e import oidc_client_app, PASSWORD


@pytest.mark.e2e
async def test_token_lifecycle_e2e(
    page: Page,
    db_session: AsyncSession,
    make_user,
    oidc_client_app: dict,
    live_server: str,
):
    # 1. Register clients & user
    client_id_1 = "client-1"
    client_secret_1 = "secret-1"
    
    # We dynamically configure oidc_client_app to use client-1 and secret-1
    oidc_client_app["client_config"]["client_id"] = client_id_1
    oidc_client_app["client_config"]["client_secret"] = client_secret_1

    user = await make_user(
        login="oidc_lifecycle_user",
        email="oidc_lifecycle_user@example.com",
        nickname="OIDC Lifecycle User",
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
            "client_name": "Lifecycle Client 1",
            "client_uri": oidc_client_app["base_url"],
            "scope": "openid email profile",
            "redirect_uris": [oidc_client_app["redirect_uri"]],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post",
        }
    )
    db_session.add(client_1)

    # Register client-2 (the introspecting non-owner)
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
            "client_name": "Lifecycle Client 2",
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

    # 2. Start browser login and consent for client-1
    await page.goto(oidc_client_app["base_url"], wait_until="domcontentloaded")
    await expect(page.get_by_text("Sign in")).to_be_visible()
    await page.get_by_label("Email or Login").fill("oidc_lifecycle_user")
    await page.get_by_label("Password").fill(PASSWORD)
    await page.get_by_role("button", name="Login", exact=True).click()
    await expect(
        page.get_by_text("Lifecycle Client 1 wants to access")
    ).to_be_visible()
    await page.get_by_role("button", name="Allow access").click()

    await expect(page.get_by_text("OIDC flow complete")).to_be_visible()

    # 3. Retrieve first client's initial tokens
    result = oidc_client_app["result"]
    assert result["token_status"] == HTTPStatus.OK
    token = result["token"]
    
    access_token = token["access_token"]
    refresh_token = token["refresh_token"]
    
    assert access_token is not None
    assert refresh_token is not None

    async with httpx.AsyncClient() as client:
        # A. Introspection (active token, owning client)
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

        # B. Introspection (non-owning client tries to inspect client-1's token)
        resp = await client.post(
            f"{live_server}/oauth/introspect",
            data={"token": access_token},
            auth=(client_id_2, client_secret_2),
        )
        assert resp.status_code == HTTPStatus.OK
        intro_2 = resp.json()
        assert intro_2["active"] is False  # Must be false for unauthorized client

        # C. UserInfo flow (requesting with openid+email+profile scope)
        resp = await client.get(
            f"{live_server}/oauth/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert resp.status_code == HTTPStatus.OK
        userinfo = resp.json()
        assert userinfo["sub"] == str(user.id)
        assert userinfo["email"] == "oidc_lifecycle_user@example.com"
        assert userinfo["name"] == "OIDC Lifecycle User"
        assert "lnurl_pubkey" in userinfo

        # D. UserInfo scope protection (using a token with only openid+email, lacking profile)
        token_no_profile_value = "access-token-no-profile"
        token_no_profile = OAuth2Token(
            client_id=client_id_1,
            user_id=user.id,
            token_type="Bearer",
            access_token=token_no_profile_value,
            refresh_token="refresh-token-no-profile",
            scope="openid email",
            issued_at=int(time.time()),
            expires_in=3600,
        )
        db_session.add(token_no_profile)
        await db_session.commit()

        resp = await client.get(
            f"{live_server}/oauth/userinfo",
            headers={"Authorization": f"Bearer {token_no_profile_value}"},
        )
        # Should reject because it lacks the "profile" scope required by userinfo
        assert resp.status_code in (HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN)

        # E. Refresh Token Grant & Rotation
        resp = await client.post(
            f"{live_server}/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client_id_1,
                "client_secret": client_secret_1,
            },
        )
        assert resp.status_code == HTTPStatus.OK
        refresh_res = resp.json()
        new_access_token = refresh_res["access_token"]
        new_refresh_token = refresh_res["refresh_token"]

        assert new_access_token != access_token
        assert new_refresh_token != refresh_token

        # Verify new access token is active
        resp = await client.post(
            f"{live_server}/oauth/introspect",
            data={"token": new_access_token},
            auth=(client_id_1, client_secret_1),
        )
        assert resp.status_code == HTTPStatus.OK
        assert resp.json()["active"] is True

        # F. Old Refresh Token Rejection
        resp = await client.post(
            f"{live_server}/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,  # Try old one again
                "client_id": client_id_1,
                "client_secret": client_secret_1,
            },
        )
        assert resp.status_code == HTTPStatus.BAD_REQUEST
        assert resp.json()["error"] == "invalid_grant"

        # G. Revocation
        resp = await client.post(
            f"{live_server}/oauth/revoke",
            data={"token": new_access_token, "token_type_hint": "access_token"},
            auth=(client_id_1, client_secret_1),
        )
        assert resp.status_code == HTTPStatus.OK

        # H. Verification after revocation
        resp = await client.post(
            f"{live_server}/oauth/introspect",
            data={"token": new_access_token},
            auth=(client_id_1, client_secret_1),
        )
        assert resp.status_code == HTTPStatus.OK
        assert resp.json()["active"] is False

        resp = await client.get(
            f"{live_server}/oauth/userinfo",
            headers={"Authorization": f"Bearer {new_access_token}"},
        )
        assert resp.status_code in (HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN)
