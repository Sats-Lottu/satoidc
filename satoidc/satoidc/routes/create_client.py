import time
from secrets import token_urlsafe
from typing import Annotated
from urllib.parse import urlparse
from uuid import UUID

from fastapi import Depends, Request
from nicegui import APIRouter, ui
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth.security import page_security
from satoidc.enums import (
    GrantTypeEnum,
    ResponseTypeEnum,
    TokenEndpointAuthMethodEnum,
)
from satoidc.models import OAuth2Client
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

router = APIRouter()
Session = Annotated[AsyncSession, Depends(get_session)]

SUPPORTED_GRANT_TYPES = {
    GrantTypeEnum.AUTHORIZATION_CODE.value,
    GrantTypeEnum.REFRESH_TOKEN.value,
}
SUPPORTED_RESPONSE_TYPES = {ResponseTypeEnum.CODE.value}
SUPPORTED_SCOPES = {"openid", "profile", "email"}
SUPPORTED_AUTH_METHODS = {
    method.value for method in TokenEndpointAuthMethodEnum
}


class ClientMetadataValidationError(ValueError):
    def __init__(self, messages: list[str]):
        self.messages = messages
        super().__init__("; ".join(messages))


def parse_multiline_values(value: str | None) -> list[str]:
    return [
        line.strip()
        for line in (value or "").splitlines()
        if line.strip()
    ]


def _is_absolute_http_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _parse_scope(value: str | None) -> str:
    requested_scopes = [scope.strip() for scope in (value or "").split()]
    return " ".join(dict.fromkeys(requested_scopes))


def build_client_metadata(  # noqa: PLR0912, PLR0913
    *,
    client_name: str | None,
    client_uri: str | None,
    scope: str | None,
    redirect_uri: str | None,
    grant_type: str | None,
    response_type: str | None,
    token_endpoint_auth_method: str | None,
) -> dict:
    errors: list[str] = []
    name = (client_name or "").strip()
    uri = (client_uri or "").strip()
    scopes = _parse_scope(scope)
    redirect_uris = parse_multiline_values(redirect_uri)
    grant_types = parse_multiline_values(grant_type)
    response_types = parse_multiline_values(response_type)
    auth_method = (
        token_endpoint_auth_method
        or TokenEndpointAuthMethodEnum.CLIENT_SECRET_BASIC.value
    )

    if not name:
        errors.append("Client name is required.")
    if uri and not _is_absolute_http_url(uri):
        errors.append("Client URI must be an absolute HTTP(S) URL.")
    if not redirect_uris:
        errors.append("At least one redirect URI is required.")
    for redirect in redirect_uris:
        if not _is_absolute_http_url(redirect):
            errors.append(
                f"Redirect URI must be an absolute HTTP(S) URL: {redirect}"
            )

    unsupported_grants = sorted(set(grant_types) - SUPPORTED_GRANT_TYPES)
    unsupported_responses = sorted(
        set(response_types) - SUPPORTED_RESPONSE_TYPES
    )
    unsupported_scopes = sorted(set(scopes.split()) - SUPPORTED_SCOPES)
    if not grant_types:
        errors.append("At least one grant type is required.")
    if unsupported_grants:
        errors.append(
            "Unsupported grant types: " + ", ".join(unsupported_grants)
        )
    if not response_types:
        errors.append("At least one response type is required.")
    if unsupported_responses:
        errors.append(
            "Unsupported response types: " + ", ".join(unsupported_responses)
        )
    if ResponseTypeEnum.CODE.value in response_types and (
        GrantTypeEnum.AUTHORIZATION_CODE.value not in grant_types
    ):
        errors.append(
            "The code response type requires the authorization_code grant."
        )
    if not scopes:
        errors.append("At least one scope is required.")
    if unsupported_scopes:
        errors.append("Unsupported scopes: " + ", ".join(unsupported_scopes))
    if auth_method not in SUPPORTED_AUTH_METHODS:
        errors.append(f"Unsupported token endpoint auth method: {auth_method}")

    if errors:
        raise ClientMetadataValidationError(errors)

    return {
        "client_name": name,
        "client_uri": uri,
        "grant_types": grant_types,
        "redirect_uris": redirect_uris,
        "response_types": response_types,
        "scope": scopes,
        "token_endpoint_auth_method": auth_method,
    }


@router.page("/create_client")
@page_security(permissions=["developer", "admin"])
async def create_client_page(
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
                    client_metadata = build_client_metadata(
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

                client.set_client_metadata(client_metadata)
                session.add(client)
                await session.commit()

                with ui.dialog() as dialog, ui.card().classes(DIALOG_CLASSES):
                    ui.label("Client created").classes(
                        "text-xl font-semibold"
                    )
                    ui.label(
                        "Copy the credentials now. The client secret is only "
                        "shown at creation time."
                    ).classes(MUTED_TEXT)
                    for label, value in {
                        "Client ID": client_id,
                        "Client Secret": secret or "Public client: no secret",
                    }.items():
                        with ui.column().classes("gap-1 w-full"):
                            ui.label(label).classes(f"text-sm {MUTED_TEXT}")
                            ui.label(value).classes(TECH_TEXT)
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
