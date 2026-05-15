from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import func, select

from satoidc.auth.permissions import (
    PermissionRequestNotAllowed,
    PermissionRequestNotFound,
    approve_permission_request,
    cancel_permission_request,
    create_permission_request,
    deny_permission_request,
    get_admin_dashboard_metrics,
    get_latest_permission_request,
    get_pending_permission_request_count,
    has_developer_access,
    list_permission_requests,
)
from satoidc.enums import PermissionRequestStatusEnum, PermissionsEnum
from satoidc.models import OAuth2Client, Permission, PermissionRequest

EXPECTED_TOTAL_USERS = 3


def test_developer_access_includes_developer_admin_and_root():
    assert has_developer_access({PermissionsEnum.DEVELOPER})
    assert has_developer_access({PermissionsEnum.ADMIN})
    assert has_developer_access({PermissionsEnum.ROOT})
    assert not has_developer_access({PermissionsEnum.SUPPORT})
    assert has_developer_access({"developer"})


async def test_create_permission_request_persists_pending_request(
    db_session, make_user
):
    user = await make_user()

    permission_request = await create_permission_request(
        db_session,
        user.id,
        reason="I need an OIDC client.",
    )
    await db_session.commit()

    stored_request = await db_session.scalar(
        select(PermissionRequest).where(
            PermissionRequest.id == permission_request.id
        )
    )

    assert stored_request is not None
    assert stored_request.requester_id == user.id
    assert stored_request.permission_type == PermissionsEnum.DEVELOPER
    assert stored_request.status == PermissionRequestStatusEnum.PENDING
    assert stored_request.reason == "I need an OIDC client."


async def test_create_permission_request_reuses_existing_pending_request(
    db_session, make_user
):
    user = await make_user()

    first_request = await create_permission_request(db_session, user.id)
    second_request = await create_permission_request(db_session, user.id)
    await db_session.commit()

    request_count = await db_session.scalar(
        select(func.count(PermissionRequest.id)).where(
            PermissionRequest.requester_id == user.id
        )
    )
    assert second_request.id == first_request.id
    assert request_count == 1


async def test_list_and_latest_permission_requests_filter_by_status(
    db_session, make_user
):
    requester = await make_user()
    admin = await make_user(
        login="admin1",
        email="admin@example.com",
        nickname="Admin",
    )
    first_request = await create_permission_request(
        db_session,
        requester.id,
        permission_type=PermissionsEnum.SUPPORT,
        reason="first",
    )
    await approve_permission_request(
        db_session, first_request.id, actor_id=admin.id
    )
    second_request = await create_permission_request(
        db_session,
        requester.id,
        permission_type=PermissionsEnum.SUPPORT,
        reason="second",
    )
    first_request.created_at = datetime.now(timezone.utc) - timedelta(days=1)
    await db_session.commit()

    pending_requests = await list_permission_requests(
        db_session, status=PermissionRequestStatusEnum.PENDING
    )
    latest_request = await get_latest_permission_request(
        db_session, requester.id, PermissionsEnum.SUPPORT
    )

    assert [request.id for request in pending_requests] == [
        second_request.id
    ]
    assert latest_request.id == second_request.id
    assert latest_request.reason == "second"


async def test_create_permission_request_rejects_existing_developer_access(
    db_session, make_user
):
    user = await make_user()
    db_session.add(
        Permission(
            user_id=user.id,
            granted_by=None,
            permission_type=PermissionsEnum.DEVELOPER,
            expiration_date=None,
            reason="already granted",
        )
    )
    await db_session.commit()

    with pytest.raises(PermissionRequestNotAllowed):
        await create_permission_request(db_session, user.id)


async def test_approve_permission_request_grants_developer_permission(
    db_session, make_user
):
    requester = await make_user()
    admin = await make_user(
        login="admin1",
        email="admin@example.com",
        nickname="Admin",
    )
    permission_request = await create_permission_request(
        db_session, requester.id
    )
    await db_session.commit()

    approved_request = await approve_permission_request(
        db_session,
        permission_request.id,
        actor_id=admin.id,
        decision_reason="Looks valid.",
    )
    await db_session.commit()

    granted_permission = await db_session.scalar(
        select(Permission).where(
            Permission.user_id == requester.id,
            Permission.permission_type == PermissionsEnum.DEVELOPER,
        )
    )

    assert approved_request.status == PermissionRequestStatusEnum.APPROVED
    assert approved_request.decided_by == admin.id
    assert approved_request.decision_reason == "Looks valid."
    assert granted_permission is not None
    assert granted_permission.granted_by == admin.id
    assert granted_permission.disabled is False


async def test_approve_permission_request_uses_default_reason(
    db_session, make_user
):
    requester = await make_user()
    admin = await make_user(
        login="admin1",
        email="admin@example.com",
        nickname="Admin",
    )
    permission_request = await create_permission_request(
        db_session, requester.id
    )
    await db_session.commit()

    await approve_permission_request(
        db_session,
        permission_request.id,
        actor_id=admin.id,
    )
    await db_session.commit()
    permission = await db_session.scalar(
        select(Permission).where(
            Permission.user_id == requester.id,
            Permission.permission_type == PermissionsEnum.DEVELOPER,
        )
    )

    assert permission.reason == "Approved permission request"


async def test_approve_permission_request_reenables_existing_permission(
    db_session, make_user
):
    requester = await make_user()
    admin = await make_user(
        login="admin1",
        email="admin@example.com",
        nickname="Admin",
    )
    db_session.add(
        Permission(
            user_id=requester.id,
            granted_by=None,
            permission_type=PermissionsEnum.DEVELOPER,
            expiration_date=datetime.now(timezone.utc) - timedelta(days=1),
            disabled=True,
            reason="old",
        )
    )
    permission_request = await create_permission_request(
        db_session, requester.id
    )
    await db_session.commit()

    await approve_permission_request(
        db_session,
        permission_request.id,
        actor_id=admin.id,
        decision_reason="reactivate",
    )
    await db_session.commit()
    permission = await db_session.scalar(
        select(Permission).where(
            Permission.user_id == requester.id,
            Permission.permission_type == PermissionsEnum.DEVELOPER,
        )
    )

    assert permission.disabled is False
    assert permission.expiration_date is None
    assert permission.granted_by == admin.id
    assert permission.reason == "reactivate"


async def test_deny_permission_request_does_not_grant_permission(
    db_session, make_user
):
    requester = await make_user()
    admin = await make_user(
        login="admin1",
        email="admin@example.com",
        nickname="Admin",
    )
    permission_request = await create_permission_request(
        db_session, requester.id
    )
    await db_session.commit()

    denied_request = await deny_permission_request(
        db_session,
        permission_request.id,
        actor_id=admin.id,
        decision_reason="Need more context.",
    )
    await db_session.commit()

    granted_permission = await db_session.scalar(
        select(Permission).where(
            Permission.user_id == requester.id,
            Permission.permission_type == PermissionsEnum.DEVELOPER,
        )
    )

    assert denied_request.status == PermissionRequestStatusEnum.DENIED
    assert denied_request.decided_by == admin.id
    assert denied_request.decision_reason == "Need more context."
    assert granted_permission is None


async def test_decided_permission_request_is_idempotent(
    db_session, make_user
):
    requester = await make_user()
    admin = await make_user(
        login="admin1",
        email="admin@example.com",
        nickname="Admin",
    )
    permission_request = await create_permission_request(
        db_session, requester.id
    )
    await db_session.commit()

    await approve_permission_request(
        db_session,
        permission_request.id,
        actor_id=admin.id,
    )
    await deny_permission_request(
        db_session,
        permission_request.id,
        actor_id=admin.id,
        decision_reason="too late",
    )
    await db_session.commit()

    stored_request = await db_session.get(
        PermissionRequest, permission_request.id
    )
    permission_count = await db_session.scalar(
        select(Permission).where(
            Permission.user_id == requester.id,
            Permission.permission_type == PermissionsEnum.DEVELOPER,
        )
    )

    assert stored_request.status == PermissionRequestStatusEnum.APPROVED
    assert permission_count is not None


async def test_approve_permission_request_ignores_denied_request(
    db_session, make_user
):
    requester = await make_user()
    admin = await make_user(
        login="admin1",
        email="admin@example.com",
        nickname="Admin",
    )
    permission_request = await create_permission_request(
        db_session, requester.id
    )
    await deny_permission_request(
        db_session,
        permission_request.id,
        actor_id=admin.id,
        decision_reason="not yet",
    )
    await db_session.commit()

    unchanged_request = await approve_permission_request(
        db_session,
        permission_request.id,
        actor_id=admin.id,
        decision_reason="late approval",
    )
    permission = await db_session.scalar(
        select(Permission).where(
            Permission.user_id == requester.id,
            Permission.permission_type == PermissionsEnum.DEVELOPER,
        )
    )

    assert unchanged_request.status == PermissionRequestStatusEnum.DENIED
    assert unchanged_request.decision_reason == "not yet"
    assert permission is None


async def test_cancel_permission_request_only_cancels_requester_pending(
    db_session, make_user
):
    requester = await make_user()
    other_user = await make_user(
        login="other1",
        email="other@example.com",
        nickname="Other",
    )
    permission_request = await create_permission_request(
        db_session, requester.id
    )
    await db_session.commit()

    unchanged_request = await cancel_permission_request(
        db_session, permission_request.id, requester_id=other_user.id
    )
    assert unchanged_request.status == PermissionRequestStatusEnum.PENDING

    cancelled_request = await cancel_permission_request(
        db_session, permission_request.id, requester_id=requester.id
    )
    await db_session.commit()

    assert cancelled_request.status == PermissionRequestStatusEnum.CANCELLED


async def test_permission_request_mutations_reject_unknown_request(db_session):
    with pytest.raises(PermissionRequestNotFound):
        await approve_permission_request(
            db_session,
            999,
            actor_id=uuid4(),
        )


async def test_admin_dashboard_metrics_count_operational_views(
    db_session, make_user
):
    requester = await make_user()
    admin = await make_user(
        login="admin1",
        email="admin@example.com",
        nickname="Admin",
    )
    developer = await make_user(
        login="dev123",
        email="dev@example.com",
        nickname="Dev",
    )
    db_session.add_all(
        [
            Permission(
                user_id=developer.id,
                granted_by=admin.id,
                permission_type=PermissionsEnum.DEVELOPER,
                expiration_date=None,
                reason="developer",
            ),
            Permission(
                user_id=requester.id,
                granted_by=admin.id,
                permission_type=PermissionsEnum.SUPPORT,
                expiration_date=datetime.now(timezone.utc)
                - timedelta(days=1),
                reason="expired",
            ),
            OAuth2Client(
                user_id=developer.id,
                client_id="client-1",
                client_id_issued_at=int(datetime.now(timezone.utc).timestamp()),
                client_secret="secret",
            ),
        ]
    )
    await create_permission_request(db_session, requester.id)
    await db_session.commit()

    metrics = await get_admin_dashboard_metrics(db_session)
    pending_count = await get_pending_permission_request_count(db_session)

    assert metrics.pending_requests == 1
    assert pending_count == 1
    assert metrics.total_users == EXPECTED_TOTAL_USERS
    assert metrics.developer_access_users == 1
    assert metrics.registered_clients == 1
    assert metrics.recently_created_clients == 1
    assert metrics.inactive_permissions == 1
