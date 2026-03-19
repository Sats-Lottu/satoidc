from typing import Annotated
from uuid import UUID

from fastapi import Depends, Request
from nicegui import APIRouter, ui
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth.security import page_security
from satoidc.models import OAuth2Client
from satoidc.models.database import get_session

router = APIRouter(prefix="/dashboard")

Session = Annotated[AsyncSession, Depends(get_session)]


@router.page("/admin", dark=True)
@page_security()
async def dashboard_admin():
    with ui.header().classes(
        "justify-between items-center bg-transparent border-b border-gray-700"
    ):
        ui.label("Dashboard Admin").classes("text-2xl font-bold")
        with ui.row().classes("items-center"):
            with ui.menu() as menu:
                ui.menu_item("asdf")
            ui.button(icon="circle_notifications", on_click=menu.open).classes(
                "bg-transparent"
            )
            with ui.dropdown_button(
                "Admin", icon="person", auto_close=True
            ).classes("bg-transparent"):
                ui.item("Profile", on_click=lambda: ui.navigate.to("/profile"))
                ui.item("Logout", on_click=lambda: ui.navigate.to("/logout"))
    with ui.list().props("bordered separator").classes("self-center"):
        ui.item_label("Permissions Requested").props("header").classes(
            "text-bold"
        )
        ui.separator()
        with ui.item():
            with ui.item_section().props("avatar"):
                ui.icon("person")
            with ui.item_section():
                ui.item_label("Satoshi")
                ui.item_label("name").props("caption")
            with ui.item_section():
                ui.item_label("Developer")
                ui.item_label("permission").props("caption")
            with ui.item_section().props("side").classes("items-center gap-2"):
                ui.button("Approve", icon="check", color="green").classes(
                    "w-full"
                )
                ui.button("Deny", icon="close", color="red").classes("w-full")


@router.page("/developer", dark=True)
@page_security(permissions=["developer"])
async def dashboard_developer(session: Session, request: Request):
    user_id = request.session.get("user_id")
    with ui.header().classes(
        "justify-between items-center bg-transparent border-b border-gray-700"
    ):
        ui.label("Dashboard Developer").classes("text-2xl font-bold")
        with ui.dropdown_button("Dev", icon="person", auto_close=True).classes(
            "bg-transparent"
        ):
            ui.item("Profile", on_click=lambda: ui.navigate.to("/profile"))
            ui.item("Logout", on_click=lambda: ui.navigate.to("/logout"))

    # obter sessão do banco
    clients = await session.scalars(
        select(OAuth2Client).where(OAuth2Client.client_id == UUID(user_id))
    )

    columns = [
        {"name": "name", "label": "Name", "field": "name"},
        {"name": "users", "label": "Users", "field": "users"},
        {
            "name": "license_expiry",
            "label": "License Expiry",
            "field": "license_expiry",
        },
        {"name": "action", "label": "Action", "align": "center"},
    ]
    rows = [
        {
            "name": client.client_name,
            "users": 0,
            "license_expiry": "12/12/2999",
        }
        for client in clients
    ]
    with ui.column().classes(
        "items-center self-center w-full max-w-screen-md mx-auto"
    ):
        ui.label("OAuth2 Clients").classes("text-2xl font-bold mb-4")
        table = ui.table(columns=columns, rows=rows).classes("w-full")
        with table.add_slot("body-cell-action"):
            with table.cell("action"):
                ui.button("Notify").props("flat").on(
                    "click",
                    js_handler="() => emit(props.row.name)",
                    handler=lambda e: ui.notify(e.args),
                )
        with ui.row().classes("items-center justify-between w-full"):
            with ui.row().classes("items-center"):
                ui.icon("search", size="20px")
                ui.input("Search").bind_value(table, "filter")
            ui.button(
                "New Client", on_click=lambda: ui.navigate.to("/create_client")
            )

    """# container principal
    for client in clients:
        # equivalente ao <pre>
        with ui.card().classes("w-full p-4 bg-gray-900 text-white"):
            ui.label("Client Info").classes("font-bold text-lg")

            # client_info
            if client.client_info:
                for key, value in client.client_info.items():
                    with ui.row().classes("gap-2"):
                        ui.label(f"{key}:").classes("font-bold")
                        ui.label(str(value))

            ui.separator()

            ui.label("Client Metadata").classes("font-bold text-lg")

            # client_metadata
            if client.client_metadata:
                for key, value in client.client_metadata.items():
                    with ui.row().classes("gap-2"):
                        ui.label(f"{key}:").classes("font-bold")
                        ui.label(str(value))

        ui.separator()"""
