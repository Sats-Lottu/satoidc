# ruff: noqa: PLR1702

from typing import Annotated
from urllib.parse import urlparse
from uuid import UUID

from fastapi import Depends, Request
from fastapi.responses import RedirectResponse
from nicegui import APIRouter, ui
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth.client_management import ClientMetadataValidationError
from satoidc.auth.security import is_authorized, page_security
from satoidc.enums import (
    GrantTypeEnum,
    PermissionsEnum,
    ResponseTypeEnum,
    TokenEndpointAuthMethodEnum,
)
from satoidc.models import Permission
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
from satoidc.schemas.oauth_clients import CreateOAuthClientCommandForm
from satoidc.services.oauth_clients import create_oauth_client

router = APIRouter()
Session = Annotated[AsyncSession, Depends(get_session)]

CLIENT_TYPE_PUBLIC = "public_browser_mobile"
CLIENT_TYPE_CONFIDENTIAL = "confidential_web"


def _create_client_redirect() -> RedirectResponse:
    return RedirectResponse("/create_client", status_code=303)


def _client_form_scopes(*, profile: bool, email: bool) -> str:
    scopes = ["openid"]
    if profile:
        scopes.append("profile")
    if email:
        scopes.append("email")
    return " ".join(scopes)


def _client_form_grants(*, refresh_token: bool) -> str:
    grants = [GrantTypeEnum.AUTHORIZATION_CODE.value]
    if refresh_token:
        grants.append(GrantTypeEnum.REFRESH_TOKEN.value)
    return "\n".join(grants)


def _client_form_auth_method(
    *, client_type: str, token_endpoint_auth_method: str
) -> str:
    if client_type == CLIENT_TYPE_PUBLIC:
        return TokenEndpointAuthMethodEnum.NONE.value
    return token_endpoint_auth_method


async def _authorized_client_creator(
    session: AsyncSession, user_id: UUID
) -> bool:
    result = await session.scalars(
        select(Permission.permission_type).where(
            Permission.user_id == user_id,
            Permission.disabled.is_(False),
            or_(
                Permission.expiration_date > func.now(),
                Permission.expiration_date.is_(None),
            ),
        )
    )
    return is_authorized(
        {str(permission) for permission in result.all()},
        [PermissionsEnum.DEVELOPER, PermissionsEnum.ADMIN],
        mode="any",
    )


@router.post("/dashboard/developer/clients")
async def create_client_command(
    session: Session,
    request: Request,
    form: CreateOAuthClientCommandForm,
):
    user_id = request.session.get("user_id")
    try:
        user_uuid = UUID(user_id)
    except (TypeError, ValueError):
        return RedirectResponse("/login", status_code=303)

    if not await _authorized_client_creator(session, user_uuid):
        return RedirectResponse("/forbidden", status_code=303)

    try:
        client, secret = await create_oauth_client(
            session,
            user_id=user_uuid,
            client_name=form.client_name,
            client_uri=form.client_uri,
            scope=_client_form_scopes(
                profile=form.profile_scope,
                email=form.email_scope,
            ),
            redirect_uri=form.redirect_uri,
            grant_type=_client_form_grants(
                refresh_token=form.refresh_token_enabled
            ),
            response_type=ResponseTypeEnum.CODE.value,
            token_endpoint_auth_method=_client_form_auth_method(
                client_type=form.client_type,
                token_endpoint_auth_method=form.token_endpoint_auth_method,
            ),
        )
    except ClientMetadataValidationError as error:
        request.session["create_client_flash"] = {
            "type": "error",
            "messages": error.messages,
        }
        return _create_client_redirect()

    request.session["create_client_flash"] = {
        "type": "created",
        "client_id": client.client_id,
        "client_secret": secret or "Public client: no secret",
    }
    return _create_client_redirect()


@router.page("/create_client")
@page_security(permissions=[PermissionsEnum.DEVELOPER, PermissionsEnum.ADMIN])
async def create_client_page(  # noqa: PLR0915, PLR1702
    session: Session,
    request: Request,
):  # pragma: no cover
    user_id = request.session.get("user_id")
    validation_messages: list[str] = []

    def is_public_client(client_type: str | None) -> bool:
        return client_type == "Public browser or mobile application"

    def selected_scopes() -> str:
        scopes = ["openid"]
        if profile_scope.value:
            scopes.append("profile")
        if email_scope.value:
            scopes.append("email")
        return " ".join(scopes)

    def selected_grants() -> str:
        grants = [GrantTypeEnum.AUTHORIZATION_CODE.value]
        if refresh_token_enabled.value:
            grants.append(GrantTypeEnum.REFRESH_TOKEN.value)
        return "\n".join(grants)

    def selected_auth_method() -> str:
        if is_public_client(client_type.value):
            return TokenEndpointAuthMethodEnum.NONE.value
        return token_endpoint_auth_method.value

    def validate_before_submit() -> list[str]:
        messages: list[str] = []
        if not (client_name.value or "").strip():
            messages.append("Client Name is required.")
        if not _is_http_url(client_uri.value):
            messages.append("Client URI must be an absolute HTTP(S) URL.")
        redirect_values = [
            value.strip()
            for value in (redirect_uri.value or "").splitlines()
            if value.strip()
        ]
        if not redirect_values:
            messages.append("At least one redirect URI is required.")
        elif invalid_redirects := [
            value for value in redirect_values if not _is_http_url(value)
        ]:
            messages.append(
                "Redirect URIs must be absolute HTTP(S) URLs: "
                + ", ".join(invalid_redirects[:2])
            )
        return messages

    def _is_http_url(value: str | None) -> bool:
        parsed = urlparse((value or "").strip())
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)

    @ui.refreshable
    def validation_panel() -> None:
        if not validation_messages:
            return
        with ui.element("div").classes(
            "w-full rounded-lg border border-red-500/40 bg-red-950/30 "
            "p-4 text-sm text-red-100"
        ):
            ui.label("Revise estes campos antes de criar o client.").classes(
                "font-semibold"
            )
            for message in validation_messages:
                ui.label(message)

    @ui.refreshable
    def protocol_review() -> None:
        with ui.column().classes("gap-4 w-full"):
            ui.label("Review").classes("text-xl font-semibold")
            ui.label(
                "SatOIDC will create the protocol metadata below from the "
                "friendly choices in the form."
            ).classes(MUTED_TEXT)
            for label, value in {
                "Client type": client_type.value,
                "Client authentication": selected_auth_method(),
                "Allowed scopes": selected_scopes(),
                "Grant types": selected_grants().replace("\n", ", "),
                "Response types": ResponseTypeEnum.CODE.value,
            }.items():
                with ui.column().classes("gap-1 w-full"):
                    ui.label(label).classes(f"text-sm {MUTED_TEXT}")
                    ui.label(value).classes(
                        "text-sm text-slate-100 break-all"
                    )
            with ui.element("div").classes(
                "rounded-lg border border-sky-500/30 bg-sky-950/30 p-4"
            ):
                ui.label("Safe defaults").classes("font-semibold")
                ui.label(
                    "Authorization Code and code response are fixed for v1. "
                    "Public clients do not receive a secret."
                ).classes(MUTED_TEXT)

    def refresh_guidance() -> None:
        protocol_review.refresh()

    async def submit():
        nonlocal validation_messages
        validation_messages = validate_before_submit()
        validation_panel.refresh()
        if validation_messages:
            for message in validation_messages[:3]:
                ui.notify(message, type="negative")
            return

        try:
            client, secret = await create_oauth_client(
                session,
                user_id=UUID(user_id),
                client_name=client_name.value,
                client_uri=client_uri.value,
                scope=selected_scopes(),
                redirect_uri=redirect_uri.value,
                grant_type=selected_grants(),
                response_type=ResponseTypeEnum.CODE.value,
                token_endpoint_auth_method=selected_auth_method(),
            )
        except ClientMetadataValidationError as error:
            validation_messages = error.messages
            validation_panel.refresh()
            for message in error.messages[:3]:
                ui.notify(message, type="negative")
            return

        with ui.dialog() as dialog, ui.card().classes(DIALOG_CLASSES):
            ui.label("Client created").classes("text-xl font-semibold")
            ui.label(
                "Copy the credentials now. The client secret is only shown "
                "at creation time."
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
                    on_click=lambda: ui.navigate.to("/dashboard/developer"),
                ).classes(PRIMARY_BUTTON_CLASSES)
        dialog.open()

    with page_shell("max-w-5xl"):
        with ui.column().classes("gap-2 w-full"):
            ui.label("Create OAuth2 Client").classes("text-2xl font-bold")
            ui.label(
                "Register an application with guided defaults for the "
                "Authorization Code flow."
            ).classes(MUTED_TEXT)

        with ui.grid(columns=2).classes(
            "w-full gap-6 max-lg:grid-cols-1 items-start"
        ):
            with card("gap-5"):
                ui.label("Application details").classes(
                    "text-xl font-semibold"
                )
                client_name = ui.input(
                    "Client Name",
                    placeholder="Example: Customer Portal",
                ).classes(INPUT_CLASSES)
                client_uri = (
                    ui.input(
                        "Client URI",
                        placeholder="https://app.example.com",
                    )
                    .props("type=url")
                    .classes(INPUT_CLASSES)
                )
                ui.label(
                    "Use the public home page of the application. This helps "
                    "operators recognize the client later."
                ).classes(MUTED_TEXT)

                ui.separator().classes("bg-slate-700/60")
                ui.label("Application type").classes("text-lg font-semibold")
                client_type = ui.select(
                    options=[
                        "Confidential web application",
                        "Public browser or mobile application",
                    ],
                    value="Confidential web application",
                    label="Client Type",
                    on_change=refresh_guidance,
                ).classes(INPUT_CLASSES)
                ui.label(
                    "Choose confidential for server-side apps that can keep a "
                    "secret. Choose public for browser or mobile apps."
                ).classes(MUTED_TEXT)
                token_endpoint_auth_method = ui.select(
                    options=[
                        TokenEndpointAuthMethodEnum.CLIENT_SECRET_BASIC.value,
                        TokenEndpointAuthMethodEnum.CLIENT_SECRET_POST.value,
                    ],
                    value=TokenEndpointAuthMethodEnum.CLIENT_SECRET_BASIC.value,
                    label="Client Authentication",
                    on_change=refresh_guidance,
                ).classes(INPUT_CLASSES)

                ui.separator().classes("bg-slate-700/60")
                ui.label("Permissions").classes("text-lg font-semibold")
                ui.label(
                    "OpenID is always required. Add only the profile data "
                    "this application really needs."
                ).classes(MUTED_TEXT)
                with ui.column().classes("gap-2"):
                    ui.checkbox("OpenID sign-in", value=True).props(
                        "disable"
                    )
                    profile_scope = ui.checkbox(
                        "Basic profile", value=True, on_change=refresh_guidance
                    )
                    email_scope = ui.checkbox(
                        "Email address", value=True, on_change=refresh_guidance
                    )
                    refresh_token_enabled = ui.checkbox(
                        "Allow refresh tokens",
                        value=False,
                        on_change=refresh_guidance,
                    )

                ui.separator().classes("bg-slate-700/60")
                ui.label("Redirect URIs").classes("text-lg font-semibold")
                ui.label(
                    "Add one callback URL per line. SatOIDC accepts only "
                    "absolute HTTP(S) URLs."
                ).classes(MUTED_TEXT)
                redirect_uri = (
                    ui.textarea(
                        "Redirect URIs",
                        placeholder=(
                            "https://app.example.com/auth/callback\n"
                            "http://localhost:3000/auth/callback"
                        ),
                    )
                    .props("rows=4")
                    .classes(INPUT_CLASSES)
                )
                validation_panel()
                with ui.row().classes("w-full gap-3 justify-end"):
                    ui.button(
                        "Cancel",
                        icon="close",
                        on_click=lambda: ui.navigate.to(
                            "/dashboard/developer"
                        ),
                    ).classes(SECONDARY_BUTTON_CLASSES)
                    ui.button(
                        "Create client",
                        icon="save",
                        on_click=submit,
                    ).classes(PRIMARY_BUTTON_CLASSES)

            with card("gap-5"):
                protocol_review()
