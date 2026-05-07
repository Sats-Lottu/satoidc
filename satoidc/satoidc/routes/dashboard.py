# ruff: noqa: PLR1702

from typing import Annotated
from uuid import UUID

from fastapi import Depends, Request
from nicegui import APIRouter, ui
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth.security import page_security
from satoidc.models import OAuth2Client
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
)

router = APIRouter(prefix="/dashboard")

Session = Annotated[AsyncSession, Depends(get_session)]


@router.page("/admin")
@page_security()
async def dashboard_admin():  # noqa: PLR1702
    app_header(
        title="Admin Dashboard",
        user_label="Admin",
        show_brand=False,
    )
    with ui.column().classes(PAGE):
        with ui.column().classes(f"{CONTENT} gap-6"):
            with ui.row().classes("w-full items-center justify-between"):
                ui.label("Permission Requests").classes("text-2xl font-bold")
                ui.button(icon="notifications").props(
                    'flat round aria-label="Notifications"'
                ).classes(SECONDARY_BUTTON_CLASSES).tooltip(
                    "Notifications"
                )

            with card("gap-0"):
                ui.label("Permissions Requested").classes(
                    "text-lg font-semibold mb-3"
                )
                ui.separator()
                with ui.list().classes("w-full"):
                    with ui.item():
                        with ui.item_section().props("avatar"):
                            ui.icon("person")
                        with ui.item_section():
                            ui.item_label("Satoshi")
                            ui.item_label("name").props("caption")
                        with ui.item_section():
                            ui.item_label("Developer")
                            ui.item_label("permission").props("caption")
                        with ui.item_section().props("side"):
                            with ui.row().classes("items-center gap-2"):
                                ui.button(
                                    "Approve", icon="check"
                                ).classes(PRIMARY_BUTTON_CLASSES)
                                ui.button("Deny", icon="close").classes(
                                    SECONDARY_BUTTON_CLASSES
                                )


@router.page("/developer")
@page_security(permissions=["developer"])
async def dashboard_developer(  # noqa: PLR1702
    session: Session, request: Request
):
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
                    with ui.grid(columns=2).classes(
                        "w-full gap-3 max-sm:grid-cols-1"
                    ):
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
