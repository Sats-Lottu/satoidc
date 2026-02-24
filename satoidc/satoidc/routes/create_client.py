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


@router.page("/create_client")
async def create_client_page(
    session: Session,
    request: Request,
):
    user_id = request.session.get("user_id")

    ui.link("← Home", "/").classes("text-blue-500 underline")

    ui.label("Create OAuth2 Client").classes("text-2xl font-bold mt-4")
    ui.label(f"user: {user_id}").classes("text-2xl font-bold mt-4")

    # form container
    with ui.card().classes("w-full max-w-2xl p-6 gap-4"):
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

        result = ui.label("").classes("text-green-500")

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

            result.set_text("Client created successfully!")

            # redirect after short delay
            ui.timer(
                1.0,
                lambda: ui.navigate.to("/"),
                once=True,
            )

        ui.button(
            "Submit",
            on_click=submit,
        ).classes("mt-4")
