from secrets import token_urlsafe

from authlib.oauth2 import OAuth2Error
from fastapi import Request
from nicegui import APIRouter, ui

from satoidc.auth.oauth2 import authorization
from satoidc.auth.scopes import scopes as available_scopes
from satoidc.routes.ui_components import (
    MUTED_TEXT,
    PRIMARY_BUTTON_CLASSES,
    SECONDARY_BUTTON_CLASSES,
    card,
    page_shell,
)

router = APIRouter()


def _scope_row(icon: str, title: str, description: str):  # pragma: no cover
    with ui.row().classes("w-full gap-3 items-start"):
        ui.icon(icon).classes("text-blue-400 text-2xl")
        with ui.column().classes("gap-1"):
            ui.label(title).classes("font-semibold")
            ui.label(description).classes(f"text-sm {MUTED_TEXT}")


@router.page("/authorize")
async def authorize_get(request: Request):  # pragma: no cover
    try:
        grant = authorization.validate_consent_request(request=request)
        scopes = request.query_params.get("scope", "").split()
        csrf = token_urlsafe(32)
        request.session["csrf_token"] = csrf

        action = "/oauth/authorize" + (
            ("?" + request.url.query) if request.url.query else ""
        )
        with page_shell("max-w-lg"):
            with card("gap-5"):
                ui.label(
                    f"{grant.client.client_name} wants to access your account"
                ).classes("text-xl font-bold")

                with ui.column().classes("gap-4"):
                    if "openid" in scopes:
                        _scope_row(
                            "verified_user",
                            "Identity",
                            available_scopes["openid"],
                        )
                    if "profile" in scopes:
                        _scope_row(
                            "person",
                            "View your profile",
                            available_scopes["profile"],
                        )
                    if "email" in scopes:
                        _scope_row(
                            "mail",
                            "Access your email",
                            available_scopes["email"],
                        )
                with (
                    ui.element("form")
                    .props(f"method='post' action='{action}'")
                    .classes("mt-2 w-full")
                ):
                    ui.element("input").props(
                        f"type='hidden' name='csrf_token' value='{csrf}'"
                    )
                    for key, value in request.query_params.items():
                        ui.element("input").props(
                            f"type='hidden' name='{key}' value='{value}'"
                        )

                    with ui.row().classes("gap-3 justify-between w-full"):
                        ui.button("Cancel", icon="close").props(
                            'type="submit" name="decision" value="deny" '
                            "outline"
                        ).classes(SECONDARY_BUTTON_CLASSES)
                        ui.button("Allow access", icon="check").props(
                            'type="submit" name="decision" value="approve"'
                        ).classes(PRIMARY_BUTTON_CLASSES)
                ui.label(
                    "You can revoke this access at any time in your settings."
                ).classes(f"text-xs {MUTED_TEXT}")
    except OAuth2Error as error:
        ui.notify(str(dict(error.get_body())), type="negative")
