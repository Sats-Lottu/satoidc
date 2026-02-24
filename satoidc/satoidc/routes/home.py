from typing import Annotated

from fastapi import Depends, Request
from nicegui import APIRouter, ui
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.models import OAuth2Client
from satoidc.models.database import get_session

router = APIRouter()

Session = Annotated[AsyncSession, Depends(get_session)]


@router.page("/")
async def home(session: Session, request: Request):
    user_id = request.session.get("user_id")
    ui.label(f"Logado como {user_id}").classes("text-xl font-bold")
    ui.button("Sair", on_click=lambda: ui.navigate.to("/logout")).props(
        "outline"
    )

    # obter sessão do banco
    clients = await session.scalars(
        select(OAuth2Client)  # .where(OAuth2Client.client_id == UUID(user_id))
    )

    ui.label("OAuth2 Clients").classes("text-2xl font-bold mb-4")

    # container principal
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

        ui.separator()

    # equivalente ao link
    ui.link("Create Client", "/create_client").classes(
        "text-blue-500 underline mt-4"
    )
