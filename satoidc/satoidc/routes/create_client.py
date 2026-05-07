import time
from secrets import token_urlsafe
from typing import Annotated
from uuid import UUID

from fastapi import Depends, Request
from nicegui import APIRouter, ui
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.models import OAuth2Client
from satoidc.models.database import get_session
from satoidc.routes.ui_components import (
    INPUT_CLASSES,
    MUTED_TEXT,
    PRIMARY_BUTTON_CLASSES,
    SECONDARY_BUTTON_CLASSES,
    card,
    page_shell,
)

router = APIRouter()
Session = Annotated[AsyncSession, Depends(get_session)]


@router.page("/create_client")
async def create_client_page(
    session: Session,
    request: Request,
):
    user_id = request.session.get("user_id")

    with page_shell("max-w-2xl"):
        with card("gap-4"):
            ui.label("Create OAuth2 Client").classes("text-2xl font-bold")
            ui.label(
                "Register a client application for OAuth2/OIDC flows."
            ).classes(MUTED_TEXT)
            client_name = ui.input("Client Name").classes(INPUT_CLASSES)
            client_uri = ui.input("Client URI").props("type=url").classes(
                INPUT_CLASSES
            )
            scope = ui.input("Allowed Scope").classes(INPUT_CLASSES)
            redirect_uri = (
                ui.textarea("Redirect URIs")
                .props("rows=4")
                .classes(INPUT_CLASSES)
            )
            grant_type = ui.textarea("Allowed Grant Types").props(
                "rows=4"
            ).classes(INPUT_CLASSES)
            response_type = ui.textarea("Allowed Response Types").props(
                "rows=4"
            ).classes(INPUT_CLASSES)
            token_endpoint_auth_method = ui.select(
                options=[
                    "client_secret_basic",
                    "client_secret_post",
                    "none",
                ],
                value="client_secret_basic",
                label="Token Endpoint Auth Method",
            ).classes(INPUT_CLASSES)

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
                    "token_endpoint_auth_method": (
                        token_endpoint_auth_method.value
                    ),
                }

                client.set_client_metadata(client_metadata)
                session.add(client)
                await session.commit()
                ui.notify("Client created.", type="positive")
                ui.timer(
                    1.0,
                    lambda: ui.navigate.to("/dashboard/developer"),
                    once=True,
                )

            with ui.row().classes("w-full gap-3 justify-end"):
                ui.button(
                    "Cancel",
                    icon="close",
                    on_click=lambda: ui.navigate.to("/dashboard/developer"),
                ).classes(SECONDARY_BUTTON_CLASSES)
                ui.button("Submit", icon="save", on_click=submit).classes(
                    PRIMARY_BUTTON_CLASSES
                )
