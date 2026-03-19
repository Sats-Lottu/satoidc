import time
from secrets import token_urlsafe
from typing import Annotated
from uuid import UUID

from fastapi import Depends, Request
from nicegui import APIRouter, ui
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.models import OAuth2Client
from satoidc.models.database import get_session

router = APIRouter()
Session = Annotated[AsyncSession, Depends(get_session)]


@router.page("/create_client", dark=True)
async def create_client_page(
    session: Session,
    request: Request,
):
    user_id = request.session.get("user_id")

    with ui.header(fixed=False).classes(
        "bg-transparent border-b border-gray-700 items-center justify-between"
    ):
        # lado esquerdo
        with ui.row().classes("items-center gap-0") as logo:
            ui.image("statics/imgs/logo.png").classes(
                "w-12 h-12 md:w-16 md:h-16"
            )
            ui.label("Sat").classes("text-2xl md:text-3xl font-bold")
            ui.label("OIDC").classes(
                "bg-gradient-to-r from-purple-500 via-indigo-500 to-blue-500 "
                "bg-clip-text text-transparent text-2xl md:text-3xl font-bold"
            )
            logo.on("click", lambda: ui.navigate.to("/"))

    # form container
    with ui.card().classes("w-full max-w-2xl mx-auto p-6 gap-4, self-center"):
        ui.label("Create OAuth2 Client").classes("text-2xl font-bold mt-4")
        client_name = ui.input("Client Name").classes("w-full")

        client_uri = ui.input("Client URI").props("type=url").classes("w-full")

        scope = ui.input("Allowed Scope").classes("w-full")

        redirect_uri = (
            ui.textarea("Redirect URIs").props("rows=4").classes("w-full")
        )

        grant_type = (
            ui.textarea("Allowed Grant Types")
            .props("rows=4")
            .classes("w-full")
        )

        response_type = (
            ui.textarea("Allowed Response Types")
            .props("rows=4")
            .classes("w-full")
        )

        token_endpoint_auth_method = ui.select(
            options=[
                "client_secret_basic",
                "client_secret_post",
                "none",
            ],
            value="client_secret_basic",
            label="Token Endpoint Auth Method",
        ).classes("w-full")

        async def submit():

            client_id = token_urlsafe(32)
            client_id_issued_at = int(time.time())

            secret = (
                token_urlsafe(64)
                if token_endpoint_auth_method.value != "none"
                else ""
            )
            client = OAuth2Client(
                user_id=UUID(user_id),
                client_id=client_id,
                client_id_issued_at=client_id_issued_at,
                client_secret=secret,
            )

            client_metadata = {
                "client_name": client_name.value,
                "client_uri": client_uri.value,
                "grant_types": grant_type.value.splitlines(),
                "redirect_uris": redirect_uri.value.splitlines(),
                "response_types": response_type.value.splitlines(),
                "scope": scope.value,
                "token_endpoint_auth_method": token_endpoint_auth_method.value,
            }

            client.set_client_metadata(client_metadata)

            session.add(client)
            await session.commit()

            # redirect after short delay
            ui.timer(
                1.0,
                lambda: ui.navigate.to("/"),
                once=True,
            )

        ui.button(
            "Submit",
            on_click=submit,
        ).classes("mt-4 self-center w-full")
