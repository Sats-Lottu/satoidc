from secrets import token_urlsafe

from authlib.oauth2 import OAuth2Error
from fastapi import Request
from nicegui import APIRouter, ui

from satoidc.auth.oauth2 import authorization
from satoidc.auth.scopes import scopes as avalible_scopes

router = APIRouter()


@router.page("/authorize", dark=True)
async def authorize_get(request: Request):
    # valida request de consentimento
    try:
        _grant = authorization.validate_consent_request(request=request)
        scopes = request.query_params.get("scope", "").split()
        # allowed_scopes = set(_grant.client.scope.split())
        # ui.label(f"is sub set {set(scopes).issubset(allowed_scopes)}")
        # CSRF
        csrf = token_urlsafe(32)
        request.session["csrf_token"] = csrf

        action = "/oauth/authorize" + (
            ("?" + request.url.query) if request.url.query else ""
        )
        with (
            ui.column().classes(
                "min-h-[90vh] overflow-auto self-center justify-center"
            ),
            ui.card().classes(
                "max-w-lg w-full mx-auto p-6 shadow-lg rounded-2xl"
            ),
        ):
            ui.label(
                f"{_grant.client.client_name} wants to access your account"
            ).classes("text-xl font-bold mb-4")

            with ui.column().classes("gap-4"):
                if "openid" in scopes:
                    ui.label("🔐 Identity").classes("font-semibold")

                    ui.label("✔ Identify you").classes("font-medium")
                    ui.label(f"{avalible_scopes['openid']}").classes(
                        "text-sm text-gray-500"
                    )
                if "profile" in scopes:
                    ui.label("✔ View your profile").classes("font-medium")
                    ui.label(f"{avalible_scopes['profile']}").classes(
                        "text-sm text-gray-500"
                    )
                if "email" in scopes:
                    ui.label("📧 Contact").classes("font-semibold mt-2")

                    ui.label("✔ Access your email").classes("font-medium")
                    ui.label(f"{avalible_scopes['email']}").classes(
                        "text-sm text-gray-500"
                    )
            with (
                ui.element("form")
                .props(f"method='post' action='{action}'")
                .classes("mt-4 w-full")
            ):
                # CSRF + decision
                ui.element("input").props(
                    f"type='hidden' name='csrf_token' value='{csrf}'"
                )

                # ✅ Reenvia TODOS os parâmetros OAuth como hidden
                for k, v in request.query_params.items():
                    ui.element("input").props(
                        f"type='hidden' name='{k}' value='{v}'"
                    )

                with ui.row().classes("gap-3 justify-between w-full"):
                    ui.button("Allow access").props(
                        'type="submit" name="decision" value="approve"'
                    )
                    ui.button("Cancel").props(
                        'type="submit" name="decision" value="deny" outline'
                    )
            ui.label(
                "You can revoke this access at any time in your settings."
            ).classes("text-xs text-gray-400 mt-4")
    except OAuth2Error as error:
        ui.notify(str(dict(error.get_body())))
