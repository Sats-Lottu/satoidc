import re
from urllib.parse import urlparse

import pytest
from playwright.async_api import Page, expect
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth.security import hash_password
from satoidc.enums import PermissionsEnum
from satoidc.models import OAuth2Client, Permission, PermissionRequest

PASSWORD = "StrongPass1!"


async def _login(page: Page, live_server: str, login: str) -> None:
    await page.goto(
        f"{live_server}/login?redirect_to=/profile",
        wait_until="domcontentloaded",
    )
    await page.get_by_label("Email or Login").fill(login)
    await page.get_by_label("Password").fill(PASSWORD)
    await page.get_by_role("button", name=re.compile("Login")).click()
    await expect(page).to_have_url(re.compile(r".*/profile$"))


async def _make_password_user(make_user, **kwargs):
    return await make_user(
        password_hash=hash_password(PASSWORD),
        **kwargs,
    )


async def _assert_no_horizontal_overflow(page: Page) -> None:
    overflow = await page.evaluate(
        "() => document.documentElement.scrollWidth > "
        "document.documentElement.clientWidth"
    )
    assert overflow is False


@pytest.mark.e2e
async def test_authenticated_home_and_profile_render(
    page: Page,
    live_server: str,
    make_user,
):
    await page.set_viewport_size({"width": 390, "height": 844})
    await _make_password_user(
        make_user,
        login="profile_user",
        email="profile_user@example.com",
        nickname="Profile User",
    )

    await page.goto(f"{live_server}/", wait_until="domcontentloaded")
    await expect(page.get_by_text("SatOIDC Identity Provider")).to_be_visible()
    await expect(page.get_by_role("button", name="Sign in")).to_be_visible()

    await _login(page, live_server, "profile_user")
    await expect(page.get_by_text("Account Information")).to_be_visible()
    await expect(page.get_by_text("Profile User").first).to_be_visible()
    await expect(page.get_by_text("No wallet linked")).to_be_visible()

    await page.get_by_role("button", name=re.compile("Link wallet")).click()
    await expect(
        page.get_by_text("Link Lightning wallet").first
    ).to_be_visible()
    await expect(page.locator(".q-dialog img")).to_be_visible()

    await page.goto(f"{live_server}/", wait_until="domcontentloaded")
    await expect(page.get_by_text("Profile User").first).to_be_visible()
    await expect(page.get_by_role("button", name="Sign in")).to_have_count(0)


@pytest.mark.e2e
async def test_developer_dashboard_renders_empty_state(
    page: Page,
    live_server: str,
    db_session: AsyncSession,
    make_user,
):
    developer = await _make_password_user(
        make_user,
        login="developer_user",
        email="developer_user@example.com",
        nickname="Developer User",
    )
    db_session.add(
        Permission(
            user_id=developer.id,
            granted_by=None,
            permission_type=PermissionsEnum.DEVELOPER,
            expiration_date=None,
            reason="e2e developer access",
        )
    )
    await db_session.commit()

    await _login(page, live_server, "developer_user")
    await page.goto(
        f"{live_server}/dashboard/developer", wait_until="domcontentloaded"
    )

    await expect(page.get_by_text("OAuth2 Clients")).to_be_visible()
    await expect(page.get_by_text("No clients registered")).to_be_visible()
    await expect(
        page.get_by_role("button", name="New Client").first
    ).to_be_visible()


@pytest.mark.e2e
async def test_developer_dashboard_renders_client_actions(
    page: Page,
    live_server: str,
    db_session: AsyncSession,
    make_user,
):
    developer = await _make_password_user(
        make_user,
        login="client_owner",
        email="client_owner@example.com",
        nickname="Client Owner",
    )
    client = OAuth2Client(
        user_id=developer.id,
        client_id="client-e2e",
        client_secret="secret",
        client_id_issued_at=1,
    )
    client.set_client_metadata(
        {
            "client_name": "E2E Client",
            "client_uri": "https://client.example",
            "scope": "openid profile",
            "redirect_uris": ["https://client.example/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post",
        }
    )
    db_session.add_all(
        [
            Permission(
                user_id=developer.id,
                granted_by=None,
                permission_type=PermissionsEnum.DEVELOPER,
                expiration_date=None,
                reason="e2e developer access",
            ),
            client,
        ]
    )
    await db_session.commit()

    await _login(page, live_server, "client_owner")
    await page.goto(
        f"{live_server}/dashboard/developer", wait_until="domcontentloaded"
    )

    await expect(page.get_by_text("E2E Client").first).to_be_visible()
    await expect(page.get_by_text("client-e2e").first).to_be_visible()
    await expect(page.get_by_role("button", name="Copy ID")).to_be_visible()
    await expect(page.get_by_role("button", name="Edit")).to_be_visible()
    await expect(
        page.get_by_role("button", name="Rotate secret")
    ).to_be_visible()
    await expect(page.get_by_role("button", name="Disable")).to_be_visible()
    await expect(page.get_by_role("button", name="Delete")).to_be_visible()

    await page.get_by_role("button", name="Delete").click()
    dialog = page.locator(".q-dialog")
    await expect(dialog.get_by_text("Delete OAuth2 client")).to_be_visible()
    delete_button = dialog.get_by_role("button", name="Delete")
    await expect(delete_button).to_be_disabled()

    await dialog.get_by_label('Type "E2E Client" to confirm').fill("wrong")
    await expect(delete_button).to_be_disabled()

    await dialog.get_by_label('Type "E2E Client" to confirm').fill(
        "E2E Client"
    )
    await expect(delete_button).to_be_enabled()
    await delete_button.click()

    await expect(page.get_by_text("No clients registered")).to_be_visible()
    db_session.expire_all()
    deleted_client = await db_session.scalar(
        select(OAuth2Client).where(OAuth2Client.client_id == "client-e2e")
    )
    assert deleted_client is None


@pytest.mark.e2e
async def test_create_client_validation_and_success(
    page: Page,
    live_server: str,
    db_session: AsyncSession,
    make_user,
):
    developer = await _make_password_user(
        make_user,
        login="creator_user",
        email="creator_user@example.com",
        nickname="Creator User",
    )
    db_session.add(
        Permission(
            user_id=developer.id,
            granted_by=None,
            permission_type=PermissionsEnum.DEVELOPER,
            expiration_date=None,
            reason="e2e developer access",
        )
    )
    await db_session.commit()

    await _login(page, live_server, "creator_user")
    await page.goto(
        f"{live_server}/create_client", wait_until="domcontentloaded"
    )
    await expect(page.get_by_text("Create OAuth2 Client")).to_be_visible()

    await page.get_by_role("button", name="Submit").click()
    await expect(page.get_by_text("Client Name is required.")).to_be_visible()

    await page.get_by_label("Client Name").fill("Created E2E Client")
    await page.get_by_label("Client URI").fill("https://created.example")
    await page.get_by_label("Allowed Scope").fill("openid profile")
    await page.get_by_label("Redirect URIs").fill(
        "https://created.example/callback"
    )
    await page.get_by_role("button", name="Submit").click()

    await expect(page.get_by_text("Client created")).to_be_visible()
    await expect(
        page.get_by_text("Client Secret", exact=True)
    ).to_be_visible()

    current_url = urlparse(page.url)
    assert current_url.path == "/create_client"


@pytest.mark.e2e
async def test_admin_dashboard_approves_permission_request(
    page: Page,
    live_server: str,
    db_session: AsyncSession,
    make_user,
):
    admin = await _make_password_user(
        make_user,
        login="admin_user",
        email="admin_user@example.com",
        nickname="Admin User",
    )
    requester = await _make_password_user(
        make_user,
        login="requester_user",
        email="requester_user@example.com",
        nickname="Requester User",
    )
    db_session.add_all(
        [
            Permission(
                user_id=admin.id,
                granted_by=None,
                permission_type=PermissionsEnum.ADMIN,
                expiration_date=None,
                reason="e2e admin access",
            ),
            PermissionRequest(
                requester_id=requester.id,
                permission_type=PermissionsEnum.DEVELOPER,
                reason="Need to register an OIDC test client.",
            ),
        ]
    )
    await db_session.commit()

    await _login(page, live_server, "admin_user")
    await page.goto(
        f"{live_server}/dashboard/admin", wait_until="domcontentloaded"
    )

    await expect(
        page.get_by_text("Pending Permission Requests")
    ).to_be_visible()
    await expect(page.get_by_text("requester_user").first).to_be_visible()
    await page.get_by_role("button", name="Approve").click()
    await expect(page.get_by_text("No pending requests")).to_be_visible()

    granted_permission = await db_session.scalar(
        select(Permission).where(
            Permission.user_id == requester.id,
            Permission.permission_type == PermissionsEnum.DEVELOPER,
        )
    )
    assert granted_permission is not None


@pytest.mark.e2e
async def test_admin_dashboard_pagination_desktop_and_mobile(
    page: Page,
    live_server: str,
    db_session: AsyncSession,
    make_user,
):
    admin = await _make_password_user(
        make_user,
        login="pagination_admin",
        email="pagination_admin@example.com",
        nickname="Pagination Admin",
    )
    owner = await _make_password_user(
        make_user,
        login="pagination_owner",
        email="pagination_owner@example.com",
        nickname="Pagination Owner",
    )
    requesters = []
    for index in range(6):
        requesters.append(
            await _make_password_user(
                make_user,
                login=f"requester_page_{index}",
                email=f"requester_page_{index}@example.com",
                nickname=f"Requester Page {index}",
            )
        )

    clients = []
    for index in range(6):
        client = OAuth2Client(
            user_id=owner.id,
            client_id=f"page-client-{index}",
            client_secret="secret",
            client_id_issued_at=index,
        )
        client.set_client_metadata(
            {
                "client_name": f"Page Client {index}",
                "client_uri": "https://client.example",
                "scope": "openid profile",
                "redirect_uris": ["https://client.example/callback"],
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "client_secret_post",
            }
        )
        clients.append(client)

    db_session.add_all(
        [
            Permission(
                user_id=admin.id,
                granted_by=None,
                permission_type=PermissionsEnum.ADMIN,
                expiration_date=None,
                reason="e2e admin access",
            ),
            *[
                PermissionRequest(
                    requester_id=requester.id,
                    permission_type=PermissionsEnum.DEVELOPER,
                    reason=f"Pagination request {index}",
                )
                for index, requester in enumerate(requesters)
            ],
            *clients,
        ]
    )
    await db_session.commit()

    await page.set_viewport_size({"width": 1280, "height": 900})
    await _login(page, live_server, "pagination_admin")
    await page.goto(
        f"{live_server}/dashboard/admin", wait_until="domcontentloaded"
    )

    await expect(
        page.get_by_text("Pending Permission Requests")
    ).to_be_visible()
    await expect(page.get_by_text("Page 1 of 2").first).to_be_visible()
    await expect(page.get_by_role("button", name="Approve")).to_have_count(5)

    await page.get_by_label("Pending requests next page").click()
    await expect(page.get_by_text("Page 2 of 2").first).to_be_visible()
    await expect(page.get_by_role("button", name="Approve")).to_have_count(1)
    await expect(
        page.get_by_label("Pending requests previous page")
    ).to_be_enabled()
    await _assert_no_horizontal_overflow(page)

    await page.set_viewport_size({"width": 390, "height": 844})
    await page.reload(wait_until="domcontentloaded")
    await page.get_by_label("OAuth clients next page").click()
    await expect(page.get_by_text("Page Client 0").first).to_be_visible()
    await expect(page.get_by_text("Page Client 5").first).to_have_count(0)
    await _assert_no_horizontal_overflow(page)
