# ruff: noqa: PLR1702

from typing import Annotated
from uuid import UUID

from fastapi import Depends, Request
from nicegui import APIRouter, ui
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from satoidc.auth.permissions import (
    approve_permission_request,
    deny_permission_request,
    get_admin_dashboard_metrics,
    list_permission_requests,
)
from satoidc.auth.security import page_security
from satoidc.enums import PermissionRequestStatusEnum, PermissionsEnum
from satoidc.models import OAuth2Client, Permission, User
from satoidc.models.database import get_session
from satoidc.routes.ui_components import (
    CONTENT,
    INPUT_CLASSES,
    MUTED_TEXT,
    PAGE,
    PANEL,
    PRIMARY_BUTTON_CLASSES,
    SECONDARY_BUTTON_CLASSES,
    SUCCESS_TEXT,
    TECH_TEXT,
    app_header,
    card,
    empty_state,
    responsive_grid,
)

router = APIRouter(prefix="/dashboard")

Session = Annotated[AsyncSession, Depends(get_session)]


@router.page("/admin")
@page_security(permissions=[PermissionsEnum.ADMIN])
async def dashboard_admin(  # noqa: PLR0912, PLR0915, PLR1702
    session: Session, request: Request
):  # pragma: no cover
    actor_id = UUID(request.session.get("user_id"))
    metrics = await get_admin_dashboard_metrics(session)
    pending_requests = await list_permission_requests(
        session, status=PermissionRequestStatusEnum.PENDING, limit=25
    )
    recent_decisions = await session.scalars(
        select(Permission)
        .options(selectinload(Permission.user))
        .where(Permission.permission_type == PermissionsEnum.DEVELOPER)
        .order_by(Permission.created_at.desc())
        .limit(5)
    )
    recent_permissions = list(recent_decisions.all())
    users = list(
        (
            await session.scalars(
                select(User).order_by(User.created_at.desc()).limit(10)
            )
        ).all()
    )
    clients = list(
        (
            await session.scalars(
                select(OAuth2Client)
                .order_by(OAuth2Client.client_id_issued_at.desc())
                .limit(10)
            )
        ).all()
    )
    inactive_permissions = list(
        (
            await session.scalars(
                select(Permission)
                .options(selectinload(Permission.user))
                .where(
                    (Permission.disabled.is_(True))
                    | (Permission.expiration_date <= func.now())
                )
                .order_by(Permission.created_at.desc())
                .limit(10)
            )
        ).all()
    )

    async def approve_request(permission_request_id: int):
        await approve_permission_request(
            session,
            permission_request_id,
            actor_id=actor_id,
            decision_reason="Approved in admin dashboard",
        )
        await session.commit()
        ui.notify("Developer access approved.", type="positive")
        ui.navigate.to("/dashboard/admin")

    def deny_dialog(permission_request_id: int):
        with ui.dialog() as dialog, ui.card().classes(
            "w-[calc(100vw-2rem)] max-w-lg gap-4"
        ):
            ui.label("Deny permission request").classes(
                "text-xl font-semibold"
            )
            reason = ui.textarea("Decision note").classes(INPUT_CLASSES)

            async def deny_request():
                await deny_permission_request(
                    session,
                    permission_request_id,
                    actor_id=actor_id,
                    decision_reason=reason.value,
                )
                await session.commit()
                ui.notify("Permission request denied.", type="warning")
                ui.navigate.to("/dashboard/admin")

            with ui.row().classes("justify-end gap-3 w-full"):
                ui.button("Cancel", on_click=dialog.close).classes(
                    SECONDARY_BUTTON_CLASSES
                )
                ui.button("Deny", icon="close", on_click=deny_request).classes(
                    SECONDARY_BUTTON_CLASSES
                )
        dialog.open()

    app_header(
        title="Admin Dashboard",
        user_label="Admin",
        show_brand=False,
    )
    with ui.column().classes(PAGE):
        with ui.column().classes(f"{CONTENT} gap-6"):
            with ui.row().classes(
                "w-full items-center justify-between gap-3 max-sm:flex-col "
                "max-sm:items-stretch"
            ):
                with ui.column().classes("gap-1"):
                    ui.label("Operations").classes("text-2xl font-bold")
                    ui.label(
                        "Review access requests and monitor active platform "
                        "state."
                    ).classes(MUTED_TEXT)
                ui.button(
                    f"{metrics.pending_requests} pending",
                    icon="notifications",
                ).classes(SECONDARY_BUTTON_CLASSES)

            with responsive_grid(3, "gap-4"):
                for label, value, icon in [
                    (
                        "Pending requests",
                        metrics.pending_requests,
                        "pending_actions",
                    ),
                    ("Total users", metrics.total_users, "group"),
                    (
                        "Developer access",
                        metrics.developer_access_users,
                        "code",
                    ),
                    (
                        "OAuth clients",
                        metrics.registered_clients,
                        "app_registration",
                    ),
                    (
                        "New clients, 7d",
                        metrics.recently_created_clients,
                        "update",
                    ),
                    (
                        "Inactive permissions",
                        metrics.inactive_permissions,
                        "block",
                    ),
                ]:
                    with ui.column().classes(f"{PANEL} p-4 gap-2"):
                        with ui.row().classes(
                            "items-center justify-between w-full"
                        ):
                            ui.label(label).classes(f"text-sm {MUTED_TEXT}")
                            ui.icon(icon).classes("text-sky-500")
                        ui.label(str(value)).classes("text-3xl font-bold")

            with card("gap-4"):
                with ui.row().classes(
                    "w-full items-center justify-between gap-3"
                ):
                    ui.label("Pending Permission Requests").classes(
                        "text-lg font-semibold"
                    )
                    ui.chip(str(len(pending_requests)), icon="notifications")
                if pending_requests:
                    with ui.list().classes("w-full"):
                        for permission_request in pending_requests:
                            requester = permission_request.requester
                            identity = (
                                requester.login
                                or requester.email
                                or requester.nickname
                                or str(requester.id)
                            )
                            with ui.item().classes(
                                "rounded-lg border border-slate-200/70 "
                                "dark:border-white/10 my-2"
                            ):
                                with ui.item_section().props("avatar"):
                                    ui.icon("person")
                                with ui.item_section():
                                    ui.item_label(identity)
                                    ui.item_label(
                                        permission_request.reason
                                        or "No requester note"
                                    ).props("caption")
                                with ui.item_section():
                                    ui.item_label(
                                        str(
                                            permission_request.permission_type
                                        )
                                    )
                                    ui.item_label("permission").props(
                                        "caption"
                                    )
                                with ui.item_section().props("side"):
                                    with ui.row().classes(
                                        "items-center gap-2 flex-wrap "
                                        "justify-end"
                                    ):
                                        request_id = permission_request.id

                                        async def approve_current(
                                            request_id=request_id,
                                        ):
                                            await approve_request(request_id)

                                        def deny_current(
                                            request_id=request_id,
                                        ):
                                            deny_dialog(request_id)

                                        ui.button(
                                            "Approve",
                                            icon="check",
                                            on_click=approve_current,
                                        ).classes(PRIMARY_BUTTON_CLASSES)
                                        ui.button(
                                            "Deny",
                                            icon="close",
                                            on_click=deny_current,
                                        ).classes(SECONDARY_BUTTON_CLASSES)
                else:
                    empty_state(
                        icon="task_alt",
                        title="No pending requests",
                        body=(
                            "Developer access requests will appear here when "
                            "users submit them from profile."
                        ),
                    )

            with responsive_grid(2, "gap-6"):
                with card("gap-4"):
                    ui.label("Recent Developer Grants").classes(
                        "text-lg font-semibold"
                    )
                    if recent_permissions:
                        with ui.list().classes("w-full"):
                            for permission in recent_permissions:
                                user = permission.user
                                ui.item_label(
                                    user.login
                                    or user.email
                                    or user.nickname
                                    or str(user.id)
                                )
                                ui.item_label(
                                    permission.reason or "Developer access"
                                ).props("caption")
                    else:
                        ui.label("No developer approvals yet.").classes(
                            MUTED_TEXT
                        )

                with card("gap-4"):
                    ui.label("Users").classes("text-lg font-semibold")
                    if users:
                        with ui.list().classes("w-full"):
                            for user in users:
                                ui.item_label(
                                    user.login
                                    or user.email
                                    or user.nickname
                                    or str(user.id)
                                )
                                ui.item_label(
                                    "active" if user.is_active else "inactive"
                                ).props("caption")
                    else:
                        ui.label("No users registered.").classes(MUTED_TEXT)

                with card("gap-4"):
                    ui.label("OAuth Clients").classes("text-lg font-semibold")
                    if clients:
                        with ui.list().classes("w-full"):
                            for client in clients:
                                metadata = client.client_metadata or {}
                                ui.item_label(
                                    metadata.get("client_name")
                                    or client.client_id
                                )
                                ui.item_label(client.client_id).props(
                                    "caption"
                                )
                    else:
                        ui.label("No clients registered.").classes(MUTED_TEXT)

                with card("gap-4"):
                    ui.label("Inactive Permissions").classes(
                        "text-lg font-semibold"
                    )
                    if inactive_permissions:
                        with ui.list().classes("w-full"):
                            for permission in inactive_permissions:
                                user = permission.user
                                ui.item_label(
                                    user.login
                                    or user.email
                                    or user.nickname
                                    or str(user.id)
                                )
                                ui.item_label(
                                    f"{permission.permission_type}"
                                ).props("caption")
                    else:
                        ui.label(
                            "No expired or disabled permissions."
                        ).classes(SUCCESS_TEXT)


@router.page("/developer")
@page_security(permissions=[PermissionsEnum.DEVELOPER, PermissionsEnum.ADMIN])
async def dashboard_developer(  # noqa: PLR1702
    session: Session, request: Request
):  # pragma: no cover
    user_id = request.session.get("user_id")
    clients = list(
        (
            await session.scalars(
                select(OAuth2Client).where(
                    OAuth2Client.user_id == UUID(user_id)
                )
            )
        ).all()
    )

    app_header(
        title="Developer Dashboard",
        user_label="Developer",
        show_brand=False,
    )
    with ui.column().classes(PAGE):
        with ui.column().classes(f"{CONTENT} gap-6"):
            with ui.row().classes(
                "w-full items-center justify-between gap-3 max-sm:flex-col "
                "max-sm:items-stretch"
            ):
                with ui.column().classes("gap-1"):
                    ui.label("OAuth2 Clients").classes("text-2xl font-bold")
                    ui.label(
                        "Manage client registrations and redirect settings."
                    ).classes(MUTED_TEXT)
                ui.button(
                    "New Client",
                    icon="add",
                    on_click=lambda: ui.navigate.to("/create_client"),
                ).classes(PRIMARY_BUTTON_CLASSES)

            columns = [
                {"name": "name", "label": "Name", "field": "name"},
                {
                    "name": "auth_method",
                    "label": "Auth Method",
                    "field": "auth_method",
                },
                {"name": "scope", "label": "Scope", "field": "scope"},
                {
                    "name": "redirect_uris",
                    "label": "Redirect URIs",
                    "field": "redirect_uris",
                },
            ]
            rows = []
            for client in clients:
                metadata = client.client_metadata or {}
                rows.append(
                    {
                        "name": (
                            metadata.get("client_name") or client.client_id
                        ),
                        "auth_method": metadata.get(
                            "token_endpoint_auth_method", "-"
                        ),
                        "scope": metadata.get("scope", "-"),
                        "redirect_uris": "\n".join(
                            metadata.get("redirect_uris") or []
                        )
                        or "-",
                    }
                )

            with card("gap-4"):
                table = ui.table(columns=columns, rows=rows).classes("w-full")
                table.props("flat bordered wrap-cells")
                with ui.row().classes(
                    "items-center justify-between w-full gap-3 "
                    "max-sm:flex-col "
                    "max-sm:items-stretch"
                ):
                    ui.input("Search").bind_value(table, "filter").classes(
                        f"max-w-sm {INPUT_CLASSES}"
                    ).props("clearable")
                    ui.label(f"{len(rows)} registered clients").classes(
                        f"text-sm {MUTED_TEXT}"
                    )

            if not clients:
                empty_state(
                    icon="app_registration",
                    title="No clients registered",
                    body="Create a client to start an OAuth2/OIDC flow.",
                    action_label="New Client",
                    action_icon="add",
                    on_action=lambda: ui.navigate.to("/create_client"),
                )

            for client in clients:
                metadata = client.client_metadata or {}
                info = client.client_info or {}
                with card("gap-4"):
                    ui.label(
                        metadata.get("client_name") or client.client_id
                    ).classes("text-lg font-semibold")
                    with responsive_grid(2, "gap-3"):
                        for key, value in {
                            "Client ID": info.get(
                                "client_id", client.client_id
                            ),
                            "Auth method": metadata.get(
                                "token_endpoint_auth_method", "-"
                            ),
                            "Scope": metadata.get("scope", "-"),
                            "Client URI": metadata.get("client_uri", "-"),
                        }.items():
                            with ui.column().classes(f"{PANEL} p-3 gap-1"):
                                ui.label(key).classes(f"text-sm {MUTED_TEXT}")
                                ui.label(str(value)).classes(
                                    TECH_TEXT
                                )
                    redirect_uris = metadata.get("redirect_uris") or []
                    with ui.column().classes("gap-2"):
                        ui.label("Redirect URIs").classes(
                            f"text-sm {MUTED_TEXT}"
                        )
                        if redirect_uris:
                            for uri in redirect_uris:
                                ui.label(uri).classes(
                                    TECH_TEXT
                                )
                        else:
                            ui.label("No redirect URIs configured").classes(
                                f"text-sm {MUTED_TEXT}"
                            )
                    ui.label("Client active").classes(
                        f"text-sm {SUCCESS_TEXT}"
                    )
