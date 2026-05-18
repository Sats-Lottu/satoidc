from datetime import datetime, timedelta, timezone

from satoidc.enums import PermissionRequestStatusEnum, PermissionsEnum
from satoidc.models import OAuth2Client, Permission, PermissionRequest, User
from satoidc.services.admin_dashboard import (
    MAX_PAGE_SIZE,
    PermissionRequestPageFilters,
    list_admin_users_page,
    list_inactive_permissions_page,
    list_oauth_clients_page,
    list_permission_requests_page,
)

USER_TOTAL = 5
PAGE_SIZE = 2
SECOND_PAGE = 2
THIRD_PAGE = 3
EMPTY_FOURTH_PAGE = 4
OWNER_CLIENT_TOTAL = 2
ONE_ITEM = 1
INACTIVE_USER_PERMISSION_TOTAL = 2
INACTIVE_DEVELOPER_TOTAL = 2


async def _make_user(db_session, index: int) -> User:
    user = User(
        lnurl_pubkey=None,
        email=f"user{index}@example.com",
        login=f"user{index}",
        password_hash=None,
        nickname=f"User {index}",
    )
    db_session.add(user)
    await db_session.flush()
    return user


async def test_admin_users_page_reports_counts_and_boundaries(db_session):
    for index in range(USER_TOTAL):
        await _make_user(db_session, index)
    await db_session.commit()

    page = await list_admin_users_page(
        db_session,
        page=SECOND_PAGE,
        page_size=PAGE_SIZE,
    )
    empty_page = await list_admin_users_page(
        db_session,
        page=EMPTY_FOURTH_PAGE,
        page_size=PAGE_SIZE,
    )
    normalized_page = await list_admin_users_page(
        db_session, page=0, page_size=200
    )

    assert len(page.items) == PAGE_SIZE
    assert page.page == SECOND_PAGE
    assert page.page_size == PAGE_SIZE
    assert page.total == USER_TOTAL
    assert page.total_pages == THIRD_PAGE
    assert page.has_previous is True
    assert page.has_next is True
    assert empty_page.items == []
    assert empty_page.total == USER_TOTAL
    assert empty_page.total_pages == THIRD_PAGE
    assert normalized_page.page == 1
    assert normalized_page.page_size == MAX_PAGE_SIZE
    assert normalized_page.errors == (
        "page must be greater than or equal to 1",
        f"page_size must be less than or equal to {MAX_PAGE_SIZE}",
    )


async def test_oauth_clients_page_handles_empty_and_owner_scope(db_session):
    owner = await _make_user(db_session, 1)
    other_owner = await _make_user(db_session, 2)
    db_session.add_all(
        [
            OAuth2Client(
                user_id=owner.id,
                client_id="owner-client-1",
                client_id_issued_at=10,
                client_secret="secret",
            ),
            OAuth2Client(
                user_id=owner.id,
                client_id="owner-client-2",
                client_id_issued_at=20,
                client_secret="secret",
            ),
            OAuth2Client(
                user_id=other_owner.id,
                client_id="other-client",
                client_id_issued_at=30,
                client_secret="secret",
            ),
        ]
    )
    await db_session.commit()

    empty_page = await list_oauth_clients_page(
        db_session, user_id=owner.id, page=2, page_size=2
    )
    scoped_page = await list_oauth_clients_page(
        db_session, user_id=owner.id, page=1, page_size=10
    )

    assert empty_page.items == []
    assert empty_page.total == OWNER_CLIENT_TOTAL
    assert scoped_page.total == OWNER_CLIENT_TOTAL
    assert {client.client_id for client in scoped_page.items} == {
        "owner-client-1",
        "owner-client-2",
    }


async def test_permission_requests_page_scopes_by_status_type_and_requester(
    db_session,
):
    requester = await _make_user(db_session, 1)
    other_requester = await _make_user(db_session, 2)
    db_session.add_all(
        [
            PermissionRequest(
                requester_id=requester.id,
                permission_type=PermissionsEnum.DEVELOPER,
                reason="pending developer",
                status=PermissionRequestStatusEnum.PENDING,
            ),
            PermissionRequest(
                requester_id=requester.id,
                permission_type=PermissionsEnum.SUPPORT,
                reason="pending support",
                status=PermissionRequestStatusEnum.PENDING,
            ),
            PermissionRequest(
                requester_id=requester.id,
                permission_type=PermissionsEnum.DEVELOPER,
                reason="approved developer",
                status=PermissionRequestStatusEnum.APPROVED,
            ),
            PermissionRequest(
                requester_id=other_requester.id,
                permission_type=PermissionsEnum.DEVELOPER,
                reason="other pending developer",
                status=PermissionRequestStatusEnum.PENDING,
            ),
        ]
    )
    await db_session.commit()

    page = await list_permission_requests_page(
        db_session,
        filters=PermissionRequestPageFilters(
            status=PermissionRequestStatusEnum.PENDING,
            permission_type=PermissionsEnum.DEVELOPER,
            requester_id=requester.id,
        ),
    )

    assert page.total == ONE_ITEM
    assert len(page.items) == ONE_ITEM
    assert page.items[0].requester_id == requester.id
    assert page.items[0].status == PermissionRequestStatusEnum.PENDING
    assert page.items[0].permission_type == PermissionsEnum.DEVELOPER
    assert page.items[0].requester.login == requester.login


async def test_inactive_permissions_page_counts_and_scopes_permissions(
    db_session,
):
    user = await _make_user(db_session, 1)
    other_user = await _make_user(db_session, 2)
    expired_at = datetime.now(timezone.utc) - timedelta(days=1)
    future_at = datetime.now(timezone.utc) + timedelta(days=1)
    db_session.add_all(
        [
            Permission(
                user_id=user.id,
                granted_by=None,
                permission_type=PermissionsEnum.DEVELOPER,
                expiration_date=None,
                reason="disabled",
                disabled=True,
            ),
            Permission(
                user_id=user.id,
                granted_by=None,
                permission_type=PermissionsEnum.SUPPORT,
                expiration_date=expired_at,
                reason="expired",
            ),
            Permission(
                user_id=other_user.id,
                granted_by=None,
                permission_type=PermissionsEnum.DEVELOPER,
                expiration_date=expired_at,
                reason="other expired",
            ),
            Permission(
                user_id=other_user.id,
                granted_by=None,
                permission_type=PermissionsEnum.SUPPORT,
                expiration_date=future_at,
                reason="active",
            ),
        ]
    )
    await db_session.commit()

    page = await list_inactive_permissions_page(
        db_session,
        user_id=user.id,
        page=1,
        page_size=1,
    )
    developer_page = await list_inactive_permissions_page(
        db_session,
        permission_type=PermissionsEnum.DEVELOPER,
    )

    assert len(page.items) == ONE_ITEM
    assert page.total == INACTIVE_USER_PERMISSION_TOTAL
    assert page.total_pages == INACTIVE_USER_PERMISSION_TOTAL
    assert all(permission.user_id == user.id for permission in page.items)
    assert developer_page.total == INACTIVE_DEVELOPER_TOTAL
    assert {
        permission.permission_type for permission in developer_page.items
    } == {PermissionsEnum.DEVELOPER}
