# ruff: noqa: PLR1702

from typing import Annotated
from uuid import UUID

from fastapi import Depends, Request
from nicegui import APIRouter, ui
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth.client_management import ClientMetadataValidationError
from satoidc.auth.security import page_security
from satoidc.enums import (
    GrantTypeEnum,
    PermissionsEnum,
    ResponseTypeEnum,
    TokenEndpointAuthMethodEnum,
)
from satoidc.models.database import get_session
from satoidc.routes.ui_components import (
    DIALOG_CLASSES,
    INPUT_CLASSES,
    MUTED_TEXT,
    PRIMARY_BUTTON_CLASSES,
    SECONDARY_BUTTON_CLASSES,
    TECH_TEXT,
    card,
    page_shell,
)
from satoidc.services.oauth_clients import create_oauth_client

router = APIRouter()
Session = Annotated[AsyncSession, Depends(get_session)]


@router.page("/create_client")
@page_security(permissions=[PermissionsEnum.DEVELOPER, PermissionsEnum.ADMIN])
async def create_client_page(  # noqa: PLR1702
    session: Session,
    request: Request,
):  # pragma: no cover
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
            scope = ui.input(
                "Allowed Scope", value="openid profile email"
            ).classes(INPUT_CLASSES)
            redirect_uri = (
                ui.textarea("Redirect URIs")
                .props("rows=4")
                .classes(INPUT_CLASSES)
            )
            grant_type = ui.textarea(
                "Allowed Grant Types",
                value=GrantTypeEnum.AUTHORIZATION_CODE.value,
            ).props("rows=4").classes(INPUT_CLASSES)
            response_type = ui.textarea(
                "Allowed Response Types", value=ResponseTypeEnum.CODE.value
            ).props("rows=4").classes(INPUT_CLASSES)
            token_endpoint_auth_method = ui.select(
                options=[
                    TokenEndpointAuthMethodEnum.CLIENT_SECRET_BASIC.value,
                    TokenEndpointAuthMethodEnum.CLIENT_SECRET_POST.value,
                    TokenEndpointAuthMethodEnum.NONE.value,
                ],
                value=TokenEndpointAuthMethodEnum.CLIENT_SECRET_BASIC.value,
                label="Token Endpoint Auth Method",
            ).classes(INPUT_CLASSES)

            async def submit():
                try:
                    client, secret = await create_oauth_client(
                        session,
                        user_id=UUID(user_id),
                        client_name=client_name.value,
                        client_uri=client_uri.value,
                        scope=scope.value,
                        redirect_uri=redirect_uri.value,
                        grant_type=grant_type.value,
                        response_type=response_type.value,
                        token_endpoint_auth_method=(
                            token_endpoint_auth_method.value
                        ),
                    )
                except ClientMetadataValidationError as error:
                    for message in error.messages[:3]:
                        ui.notify(message, type="negative")
                    return

                with ui.dialog() as dialog, ui.card().classes(DIALOG_CLASSES):
                    ui.label("Client created").classes(
                        "text-xl font-semibold"
                    )
                    ui.label(
                        "Copy the credentials now. The client secret is only "
                        "shown at creation time."
                    ).classes(MUTED_TEXT)
                    for label, value in {
                        "Client ID": client.client_id,
                        "Client Secret": secret or "Public client: no secret",
                    }.items():
                        with ui.column().classes("gap-1 w-full"):
                            ui.label(label).classes(f"text-sm {MUTED_TEXT}")
                            with ui.row().classes(
                                "w-full items-center gap-2 "
                                "max-sm:flex-col max-sm:items-stretch"
                            ):
                                ui.label(value).classes(TECH_TEXT)
                                ui.button(
                                    "Copy",
                                    icon="content_copy",
                                    on_click=lambda value=value: (
                                        ui.clipboard.write(value),
                                        ui.notify(
                                            "Copied to clipboard.",
                                            type="positive",
                                        ),
                                    ),
                                ).classes(SECONDARY_BUTTON_CLASSES)
                    with ui.row().classes("justify-end gap-3 w-full"):
                        ui.button(
                            "Back to dashboard",
                            icon="dashboard",
                            on_click=lambda: ui.navigate.to(
                                "/dashboard/developer"
                            ),
                        ).classes(PRIMARY_BUTTON_CLASSES)
                dialog.open()

            with ui.row().classes("w-full gap-3 justify-end"):
                ui.button(
                    "Cancel",
                    icon="close",
                    on_click=lambda: ui.navigate.to("/dashboard/developer"),
                ).classes(SECONDARY_BUTTON_CLASSES)
                ui.button("Submit", icon="save", on_click=submit).classes(
                    PRIMARY_BUTTON_CLASSES
                )
